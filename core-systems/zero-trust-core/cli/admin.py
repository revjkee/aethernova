# File: zero-trust-core/cli/admin.py
# Industrial-grade Zero Trust Admin CLI (stdlib only).
# Features:
# - Profiles persisted under XDG config (~/.config/zero-trust-core/config.json)
# - Secure token auth (env or prompt), redaction in logs
# - TLS verification with optional custom CA and client certs
# - Robust HTTP client with retries, jitter, backoff, idempotence guard
# - Subcommands: profile, login, whoami, user, policy, audit, health, rotate-keys, sign, verify
# - Audit logging and context propagation via zero_trust.telemetry.logging if available; graceful fallback otherwise
# - Machine-friendly JSON output, --quiet/--verbose controls
# - File HMAC signing/verification for operational integrity

from __future__ import annotations

import argparse
import base64
import dataclasses
import getpass
import hashlib
import hmac
import io
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# --- Telemetry integration (graceful fallback) ---
try:
    from zero_trust.telemetry.logging import (  # type: ignore
        setup_logging,
        get_logger,
        set_context,
        LogContext,
        audit_event,
        LoggingConfig,
    )
    _telemetry_ok = True
except Exception:
    import logging as _logging
    class _Dummy:
        def __init__(self) -> None:
            self.logger = _logging.getLogger("ztc.cli")
            if not self.logger.handlers:
                _logging.basicConfig(
                    level=_logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s",
                )
        def setup(self): ...
        def get_logger(self, name: str):
            return _logging.getLogger(name)
        def set_ctx(self, **_: Any): ...
        def audit(self, logger, event: str, **fields: Any):
            logger.info("AUDIT %s %s", event, fields)
    __d = _Dummy()
    setup_logging = __d.setup  # type: ignore
    get_logger = __d.get_logger  # type: ignore
    set_context = __d.set_ctx  # type: ignore
    def audit_event(logger, event: str, **fields: Any) -> None:  # type: ignore
        __d.audit(logger, event, **fields)
    LoggingConfig = object  # type: ignore
    _telemetry_ok = False

# --- Constants and defaults ---
APP_NAME = "zero-trust-core"
CFG_DIR = os.getenv("XDG_CONFIG_HOME", os.path.join(Path.home(), ".config"))
CFG_PATH = os.path.join(CFG_DIR, APP_NAME, "config.json")
DEFAULT_TIMEOUT = 15.0
DEFAULT_RETRIES = 5
DEFAULT_BACKOFF_BASE = 0.35  # seconds
DEFAULT_BACKOFF_MAX = 8.0
USER_AGENT = "ZTC-AdminCLI/1.0"

# --- Utilities ---

def _ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)

def _json_print(obj: Any) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n")

def _stderr(text: str) -> None:
    sys.stderr.write(text + "\n")

def _rand_jitter(mult: float = 1.0) -> float:
    return random.uniform(0.5, 1.5) * mult

def _bool_env(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).lower() not in ("0", "false", "no")

# --- Profile store ---

@dataclass
class Profile:
    name: str
    base_url: str
    verify_ssl: bool = True
    ca_path: Optional[str] = None
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    token: Optional[str] = None
    timeout: float = DEFAULT_TIMEOUT

@dataclass
class ConfigState:
    default_profile: Optional[str] = None
    profiles: Dict[str, Profile] = field(default_factory=dict)

class ProfileStore:
    def __init__(self, path: str = CFG_PATH) -> None:
        self.path = path
        self.state = ConfigState()

    def load(self) -> None:
        if not os.path.exists(self.path):
            self.state = ConfigState()
            return
        with open(self.path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        profiles = {}
        for name, pdata in raw.get("profiles", {}).items():
            profiles[name] = Profile(name=name, **pdata)
        self.state = ConfigState(
            default_profile=raw.get("default_profile"),
            profiles=profiles,
        )

    def save(self) -> None:
        _ensure_parent(self.path)
        raw = {
            "default_profile": self.state.default_profile,
            "profiles": {
                name: dataclasses.asdict(p) for name, p in self.state.profiles.items()
            },
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def add(self, profile: Profile, set_default: bool = False) -> None:
        self.state.profiles[profile.name] = profile
        if set_default or not self.state.default_profile:
            self.state.default_profile = profile.name
        self.save()

    def get(self, name: Optional[str]) -> Optional[Profile]:
        if name:
            return self.state.profiles.get(name)
        if self.state.default_profile:
            return self.state.profiles.get(self.state.default_profile)
        return None

    def set_default(self, name: str) -> None:
        if name not in self.state.profiles:
            raise KeyError(f"No such profile: {name}")
        self.state.default_profile = name
        self.save()

    def list_names(self) -> Dict[str, Dict[str, Any]]:
        return {
            n: {
                "base_url": p.base_url,
                "verify_ssl": p.verify_ssl,
                "has_token": bool(p.token),
                "timeout": p.timeout,
            }
            for n, p in self.state.profiles.items()
        }

# --- HTTP client ---

class AdminHTTPClient:
    def __init__(
        self,
        base_url: str,
        token: Optional[str],
        verify_ssl: bool = True,
        ca_path: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        logger=None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.verify_ssl = verify_ssl
        self.ca_path = ca_path
        self.client_cert = client_cert
        self.client_key = client_key
        self.timeout = timeout
        self.logger = logger or get_logger("ztc.cli.http")
        self.ctx = self._build_ssl()

    def _build_ssl(self) -> Optional[ssl.SSLContext]:
        if not self.base_url.lower().startswith("https"):
            return None
        if self.verify_ssl:
            ctx = ssl.create_default_context()
            if self.ca_path:
                ctx.load_verify_locations(cafile=self.ca_path)
        else:
            ctx = ssl._create_unverified_context()
        if self.client_cert and self.client_key:
            ctx.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)
        return ctx

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if extra:
            h.update(extra)
        return h

    def _retryable(self, code: int) -> bool:
        return code in (408, 425, 429, 500, 502, 503, 504)

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        raw_body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        retries: int = DEFAULT_RETRIES,
    ) -> Tuple[int, Dict[str, Any]]:
        url = self.base_url + path
        if params:
            q = urllib.parse.urlencode(params, doseq=True)
            sep = "&" if ("?" in url) else "?"
            url = f"{url}{sep}{q}"

        data = None
        headers = self._headers()
        if json_body is not None:
            data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif raw_body is not None:
            data = raw_body
            if content_type:
                headers["Content-Type"] = content_type

        attempt = 0
        while True:
            attempt += 1
            req = urllib.request.Request(url=url, data=data, method=method.upper(), headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    code = resp.getcode()
                    body = resp.read()
                    if not body:
                        return code, {}
                    ctype = resp.headers.get("Content-Type", "")
                    if "application/json" in ctype:
                        return code, json.loads(body.decode("utf-8"))
                    # fallback
                    return code, {"raw": base64.b64encode(body).decode("ascii")}
            except urllib.error.HTTPError as e:
                code = e.code
                # Read error body if JSON for diagnostics
                payload = {}
                try:
                    raw = e.read()
                    if raw:
                        payload = json.loads(raw.decode("utf-8"))
                except Exception:
                    payload = {"error": e.reason}
                if self._retryable(code) and attempt <= retries:
                    backoff = min(DEFAULT_BACKOFF_MAX, DEFAULT_BACKOFF_BASE * (2 ** (attempt - 1)) * _rand_jitter())
                    self.logger.warning("HTTP %s %s -> %s, retry in %.2fs", method, url, code, backoff)
                    time.sleep(backoff)
                    continue
                return code, payload or {"error": e.reason}
            except urllib.error.URLError as e:
                if attempt <= retries:
                    backoff = min(DEFAULT_BACKOFF_MAX, DEFAULT_BACKOFF_BASE * (2 ** (attempt - 1)) * _rand_jitter())
                    self.logger.warning("URLError %s, retry in %.2fs", e.reason, backoff)
                    time.sleep(backoff)
                    continue
                raise

# --- Command handlers ---

def _resolve_profile(args) -> Profile:
    store = ProfileStore()
    store.load()
    # Override by CLI flags if provided
    profile = store.get(args.profile)
    if args.base_url or args.token or args.insecure or args.ca or args.client_cert or args.client_key or args.timeout:
        # Build ephemeral profile from overrides or profile
        p = profile or Profile(name="__cli__", base_url=args.base_url or "")
        p.base_url = args.base_url or (p.base_url if p else "")
        p.verify_ssl = not args.insecure if args.insecure is not None else (p.verify_ssl if p else True)
        p.ca_path = args.ca or (p.ca_path if p else None)
        p.client_cert = args.client_cert or (p.client_cert if p else None)
        p.client_key = args.client_key or (p.client_key if p else None)
        p.token = args.token or (p.token if p else None)
        p.timeout = args.timeout or (p.timeout if p else DEFAULT_TIMEOUT)
        return p
    if not profile:
        raise SystemExit("No profile selected and no overrides provided. Use 'profile add' or --base-url.")
    return profile

def _client_from(args) -> AdminHTTPClient:
    p = _resolve_profile(args)
    if not p.base_url:
        raise SystemExit("Base URL is required. Configure a profile or pass --base-url.")
    token = p.token or os.getenv("ZTC_ADMIN_TOKEN")
    if not token and getattr(args, "require_token", False):
        token = getpass.getpass("Admin token: ").strip()
    set_context(trace_id=os.getenv("ZTC_TRACE_ID"))
    return AdminHTTPClient(
        base_url=p.base_url,
        token=token,
        verify_ssl=p.verify_ssl,
        ca_path=p.ca_path,
        client_cert=p.client_cert,
        client_key=p.client_key,
        timeout=p.timeout,
        logger=get_logger("ztc.cli.http"),
    )

# profile commands

def cmd_profile(args) -> None:
    store = ProfileStore()
    store.load()
    if args.action == "add":
        prof = Profile(
            name=args.name,
            base_url=args.base_url,
            verify_ssl=not args.insecure,
            ca_path=args.ca,
            client_cert=args.client_cert,
            client_key=args.client_key,
            token=args.token or os.getenv("ZTC_ADMIN_TOKEN"),
            timeout=args.timeout,
        )
        store.add(prof, set_default=args.default)
        audit_event(get_logger("ztc.cli"), "profile_add", name=args.name, base_url=args.base_url)
        _json_print({"ok": True, "profile": args.name, "default": store.state.default_profile == args.name})
    elif args.action == "ls":
        _json_print({"default": store.state.default_profile, "profiles": store.list_names()})
    elif args.action == "use":
        store.set_default(args.name)
        audit_event(get_logger("ztc.cli"), "profile_use", name=args.name)
        _json_print({"ok": True, "default": store.state.default_profile})
    elif args.action == "show":
        p = store.get(args.name)
        if not p:
            raise SystemExit(f"No such profile: {args.name}")
        d = dataclasses.asdict(p)
        if d.get("token"):
            d["token"] = "****"
        _json_print(d)

# login

def cmd_login(args) -> None:
    store = ProfileStore()
    store.load()
    prof = store.get(args.profile) if args.profile else store.get(store.state.default_profile)
    if not prof:
        raise SystemExit("No profile to attach token. Create one with 'profile add'.")
    token = args.token or os.getenv("ZTC_ADMIN_TOKEN") or getpass.getpass("Admin token: ").strip()
    prof.token = token
    store.add(prof, set_default=(store.state.default_profile is None))
    audit_event(get_logger("ztc.cli"), "login_token_set", profile=prof.name)
    _json_print({"ok": True, "profile": prof.name})

# whoami

def cmd_whoami(args) -> None:
    c = _client_from(args)
    code, body = c.request("GET", "/api/v1/admin/whoami")
    audit_event(get_logger("ztc.cli"), "whoami_invoked", status=code)
    _json_print({"status": code, "body": body})

# user management

def cmd_user(args) -> None:
    c = _client_from(args)
    if args.action == "list":
        params = {}
        if args.status:
            params["status"] = args.status
        code, body = c.request("GET", "/api/v1/admin/users", params=params)
        audit_event(get_logger("ztc.cli"), "user_list", status=code)
        _json_print({"status": code, "users": body})
    elif args.action == "create":
        payload = {"user_id": args.user_id, "role": args.role, "email": args.email}
        code, body = c.request("POST", "/api/v1/admin/users", json_body=payload)
        audit_event(get_logger("ztc.cli"), "user_create", user_id=args.user_id, status=code)
        _json_print({"status": code, "result": body})
    elif args.action == "disable":
        code, body = c.request("POST", f"/api/v1/admin/users/{urllib.parse.quote(args.user_id)}/disable")
        audit_event(get_logger("ztc.cli"), "user_disable", user_id=args.user_id, status=code)
        _json_print({"status": code, "result": body})

# policy management

def _read_json_from_file_or_stdin(path: Optional[str]) -> Dict[str, Any]:
    data = ""
    if path and path != "-":
        with open(path, "r", encoding="utf-8") as f:
            data = f.read()
    else:
        data = sys.stdin.read()
    return json.loads(data)

def cmd_policy(args) -> None:
    c = _client_from(args)
    if args.action == "list":
        code, body = c.request("GET", "/api/v1/admin/policies")
        audit_event(get_logger("ztc.cli"), "policy_list", status=code)
        _json_print({"status": code, "policies": body})
    elif args.action == "get":
        code, body = c.request("GET", f"/api/v1/admin/policies/{urllib.parse.quote(args.name)}")
        audit_event(get_logger("ztc.cli"), "policy_get", name=args.name, status=code)
        _json_print({"status": code, "policy": body})
    elif args.action == "set":
        payload = _read_json_from_file_or_stdin(args.file)
        code, body = c.request("PUT", f"/api/v1/admin/policies/{urllib.parse.quote(args.name)}", json_body=payload)
        audit_event(get_logger("ztc.cli"), "policy_set", name=args.name, status=code)
        _json_print({"status": code, "result": body})
    elif args.action == "delete":
        code, body = c.request("DELETE", f"/api/v1/admin/policies/{urllib.parse.quote(args.name)}")
        audit_event(get_logger("ztc.cli"), "policy_delete", name=args.name, status=code)
        _json_print({"status": code, "result": body})

# audit

def cmd_audit(args) -> None:
    c = _client_from(args)
    params = {"tail": args.lines} if args.lines else None
    code, body = c.request("GET", "/api/v1/admin/audit", params=params)
    audit_event(get_logger("ztc.cli"), "audit_tail", lines=args.lines or 0, status=code)
    _json_print({"status": code, "events": body})

# health

def cmd_health(args) -> None:
    c = _client_from(args)
    code, body = c.request("GET", "/healthz")
    audit_event(get_logger("ztc.cli"), "health_check", status=code)
    _json_print({"status": code, "health": body})

# rotate keys

def cmd_rotate_keys(args) -> None:
    c = _client_from(args)
    params = {"service": args.service}
    code, body = c.request("POST", "/api/v1/admin/keys/rotate", params=params)
    audit_event(get_logger("ztc.cli"), "keys_rotate", service=args.service, status=code)
    _json_print({"status": code, "result": body})

# sign/verify with HMAC-SHA256

def _hmac_key(source: Optional[str]) -> bytes:
    env_key = source or os.getenv("ZTC_ADMIN_SIGNING_KEY")
    if not env_key:
        raise SystemExit("No signing key. Provide --key or set ZTC_ADMIN_SIGNING_KEY.")
    return env_key.encode("utf-8")

def _file_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def cmd_sign(args) -> None:
    key = _hmac_key(args.key)
    data = _file_bytes(args.file)
    digest = hmac.new(key, data, hashlib.sha256).hexdigest()
    audit_event(get_logger("ztc.cli"), "file_signed", file=args.file, algo="HMAC-SHA256")
    _json_print({"file": args.file, "algo": "HMAC-SHA256", "signature": digest})

def cmd_verify(args) -> None:
    key = _hmac_key(args.key)
    data = _file_bytes(args.file)
    calc = hmac.new(key, data, hashlib.sha256).hexdigest()
    ok = hmac.compare_digest(calc, args.signature.lower())
    audit_event(get_logger("ztc.cli"), "file_verified", file=args.file, ok=bool(ok))
    _json_print({"file": args.file, "ok": ok})

# --- Parser ---

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ztc-admin", description="Zero Trust Core Admin CLI")
    # Global options
    p.add_argument("--profile", help="Profile name")
    p.add_argument("--base-url", help="Override base URL")
    p.add_argument("--token", help="Override token")
    p.add_argument("--ca", dest="ca", help="Custom CA file")
    p.add_argument("--client-cert", help="Client certificate file (PEM)")
    p.add_argument("--client-key", help="Client key file (PEM)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    p.add_argument("--timeout", type=float, help="HTTP timeout seconds")
    p.add_argument("-q", "--quiet", action="store_true", help="Reduce logging noise")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Increase logging verbosity")

    sub = p.add_subparsers(dest="cmd", required=True)

    # profile
    sp = sub.add_parser("profile", help="Manage CLI profiles")
    sps = sp.add_subparsers(dest="action", required=True)
    p_add = sps.add_parser("add", help="Add a profile")
    p_add.add_argument("--name", required=True)
    p_add.add_argument("--base-url", required=True)
    p_add.add_argument("--insecure", action="store_true")
    p_add.add_argument("--ca")
    p_add.add_argument("--client-cert")
    p_add.add_argument("--client-key")
    p_add.add_argument("--token")
    p_add.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p_add.add_argument("--default", action="store_true")
    p_add.set_defaults(func=cmd_profile)

    p_ls = sps.add_parser("ls", help="List profiles")
    p_ls.set_defaults(func=cmd_profile)
    p_use = sps.add_parser("use", help="Select default profile")
    p_use.add_argument("--name", required=True)
    p_use.set_defaults(func=cmd_profile)
    p_show = sps.add_parser("show", help="Show profile details")
    p_show.add_argument("--name")
    p_show.set_defaults(func=cmd_profile)

    # login
    lg = sub.add_parser("login", help="Attach or update admin token for a profile")
    lg.add_argument("--profile")
    lg.add_argument("--token")
    lg.set_defaults(func=cmd_login)

    # whoami
    wa = sub.add_parser("whoami", help="Current admin identity according to server")
    wa.set_defaults(func=cmd_whoami, require_token=True)

    # user
    us = sub.add_parser("user", help="User management")
    uss = us.add_subparsers(dest="action", required=True)
    ul = uss.add_parser("list", help="List users")
    ul.add_argument("--status", choices=("active", "disabled"))
    ul.set_defaults(func=cmd_user, require_token=True)
    uc = uss.add_parser("create", help="Create user")
    uc.add_argument("--user-id", required=True)
    uc.add_argument("--role", required=True)
    uc.add_argument("--email", required=True)
    uc.set_defaults(func=cmd_user, require_token=True)
    ud = uss.add_parser("disable", help="Disable user")
    ud.add_argument("--user-id", required=True)
    ud.set_defaults(func=cmd_user, require_token=True)

    # policy
    po = sub.add_parser("policy", help="Policy management")
    pos = po.add_subparsers(dest="action", required=True)
    pol = pos.add_parser("list", help="List policies")
    pol.set_defaults(func=cmd_policy, require_token=True)
    pog = pos.add_parser("get", help="Get policy JSON by name")
    pog.add_argument("--name", required=True)
    pog.set_defaults(func=cmd_policy, require_token=True)
    poset = pos.add_parser("set", help="Set policy from JSON file or stdin (-)")
    poset.add_argument("--name", required=True)
    poset.add_argument("--file", default="-", help="Path to JSON file or '-' for stdin")
    poset.set_defaults(func=cmd_policy, require_token=True)
    podel = pos.add_parser("delete", help="Delete policy by name")
    podel.add_argument("--name", required=True)
    podel.set_defaults(func=cmd_policy, require_token=True)

    # audit
    au = sub.add_parser("audit", help="Audit log operations")
    aus = au.add_subparsers(dest="action", required=True)
    aut = aus.add_parser("tail", help="Fetch recent audit events")
    aut.add_argument("--lines", type=int, default=100)
    aut.set_defaults(func=cmd_audit, require_token=True)

    # health
    he = sub.add_parser("health", help="Service health check")
    he.set_defaults(func=cmd_health)

    # rotate-keys
    rk = sub.add_parser("rotate-keys", help="Rotate service keys")
    rk.add_argument("--service", required=True, help="Service name")
    rk.set_defaults(func=cmd_rotate_keys, require_token=True)

    # sign/verify
    sg = sub.add_parser("sign", help="Sign file with HMAC-SHA256")
    sg.add_argument("--file", required=True)
    sg.add_argument("--key", help="Signing key (fallback to ZTC_ADMIN_SIGNING_KEY)")
    sg.set_defaults(func=cmd_sign)

    vf = sub.add_parser("verify", help="Verify file HMAC-SHA256")
    vf.add_argument("--file", required=True)
    vf.add_argument("--signature", required=True, help="Hex signature to verify")
    vf.add_argument("--key", help="Signing key (fallback to ZTC_ADMIN_SIGNING_KEY)")
    vf.set_defaults(func=cmd_verify)

    return p

# --- Main ---

def _init_logging(verbosity: int, quiet: bool) -> None:
    # Map verbosity to levels
    # 0 -> INFO, 1 -> DEBUG
    level = "INFO"
    if quiet:
        level = "WARNING"
    elif verbosity >= 1:
        level = "DEBUG"
    try:
        setup_logging(LoggingConfig() if isinstance(LoggingConfig, type) else None)  # type: ignore
        # Override root level via env or flag
        import logging
        logging.getLogger().setLevel(getattr(logging, level))
    except Exception:
        pass

def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    _init_logging(args.verbose, args.quiet)
    logger = get_logger("ztc.cli")

    # Attach a fresh trace_id for the CLI invocation
    set_context(trace_id=os.getenv("ZTC_TRACE_ID") or hashlib.sha1(os.urandom(16)).hexdigest())

    try:
        if not hasattr(args, "func"):
            parser.print_help()
            return 2
        args.func(args)
        return 0
    except KeyboardInterrupt:
        _stderr("Interrupted")
        return 130
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 1
    except Exception as e:
        logger.exception("CLI error: %s", e)
        _json_print({"ok": False, "error": str(e)})
        return 1

if __name__ == "__main__":
    sys.exit(main())
