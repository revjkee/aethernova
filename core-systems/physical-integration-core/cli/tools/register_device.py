#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI: Register (or upsert) a device in a backend over HTTPS.

Features:
- Input from JSON/YAML file, STDIN, or flags; deterministic merge priority
- Strict validation of fields; automatic device_id derivation from fingerprint if absent
- Optional Ed25519 keypair generation (requires 'cryptography' only if --gen-key used)
- Idempotency-Key support; configurable headers and API paths
- OAuth2 Bearer token and mTLS (client cert/key), custom CA or --insecure
- Retries with exponential backoff and jitter; timeouts; proxy-respecting (or --no-proxy)
- Dry-run and print-curl for reproducibility
- JSON output for success and errors suitable for automation

No external dependencies for core functionality.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import uuid
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional, Tuple, List

# --------- Utilities ---------

def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)

def join_url(base: str, path: str) -> str:
    if not base:
        return path
    return urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))

def parse_kv_pairs(items: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for it in items or []:
        if "=" not in it:
            raise ValueError(f"Invalid key=value: {it}")
        k, v = it.split("=", 1)
        out[k.strip()] = v.strip()
    return out

def deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Shallow-overwrite merge; nested dicts merged recursively."""
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)  # type: ignore
        else:
            out[k] = v
    return out

def detect_and_load_yaml(path: str) -> Optional[Dict[str, Any]]:
    """Try to read YAML using PyYAML if available; fall back to None if not installed."""
    try:
        import yaml  # type: ignore
    except Exception:
        return None
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_spec_from_file(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    if path.lower().endswith((".yaml", ".yml")):
        data = detect_and_load_yaml(path)
        if data is None:
            raise RuntimeError("YAML input requires PyYAML; install or use JSON")
        return data or {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_spec_from_stdin() -> Dict[str, Any]:
    raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        return {}
    # try JSON first
    try:
        return json.loads(raw)
    except Exception:
        pass
    # try YAML if available
    try:
        import yaml  # type: ignore
        return yaml.safe_load(raw) or {}
    except Exception:
        raise ValueError("STDIN is neither valid JSON nor YAML (or PyYAML missing)")

# --------- Model & Validation ---------

DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{3,128}$")
MODEL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
REV_RE = re.compile(r"^[A-Za-z0-9._:-]{0,32}$")
SERIAL_RE = re.compile(r"^[A-Za-z0-9._:-]{0,128}$")

@dataclass
class DeviceSpec:
    device_id: Optional[str] = None
    model: Optional[str] = None
    hw_revision: Optional[str] = None
    serial: Optional[str] = None
    site: Optional[str] = None
    labels: Dict[str, str] = None  # type: ignore
    metadata: Dict[str, Any] = None  # type: ignore
    public_key_ed25519: Optional[str] = None  # hex or base64 (auto-detected)
    twin: Dict[str, Any] = None  # type: ignore
    credentials: Dict[str, Any] = None  # optional bag

    def to_payload(self) -> Dict[str, Any]:
        d = {k: v for k, v in asdict(self).items() if v not in (None, {}, [])}
        # Normalize public key to hex if base64 provided
        pk = d.get("public_key_ed25519")
        if isinstance(pk, str):
            d["public_key_ed25519"] = normalize_pubkey(pk)
        return d

def normalize_pubkey(s: str) -> str:
    s = s.strip()
    # try hex
    try:
        _ = bytes.fromhex(s)
        return s.lower()
    except Exception:
        pass
    # try base64
    try:
        b = base64.b64decode(s, validate=True)
        return b.hex()
    except Exception:
        raise ValueError("public_key_ed25519 must be hex or base64")

def derive_device_id_if_missing(d: DeviceSpec) -> str:
    if d.device_id:
        return d.device_id
    seed = f"{d.model or ''}|{d.hw_revision or ''}|{d.serial or ''}".encode("utf-8")
    h = hashlib.sha256(seed).hexdigest()
    return f"dev-{h[:32]}"

def validate_spec(d: DeviceSpec) -> None:
    # model required
    if not d.model:
        raise ValueError("model is required")
    if not MODEL_RE.match(d.model):
        raise ValueError("model has invalid characters/length")
    # hw_revision/serial optional
    if d.hw_revision and not REV_RE.match(d.hw_revision):
        raise ValueError("hw_revision invalid")
    if d.serial and not SERIAL_RE.match(d.serial):
        raise ValueError("serial invalid")
    # device_id
    d.device_id = derive_device_id_if_missing(d)
    if not DEVICE_ID_RE.match(d.device_id):
        raise ValueError("device_id invalid (allowed A-Za-z0-9._:-, len 3..128)")
    # labels/metadata/twin default dicts
    if d.labels is None:
        d.labels = {}
    if d.metadata is None:
        d.metadata = {}
    if d.twin is None:
        d.twin = {}
    # public key if present
    if d.public_key_ed25519:
        _ = bytes.fromhex(normalize_pubkey(d.public_key_ed25519))  # will raise if invalid

def build_spec(args: argparse.Namespace) -> DeviceSpec:
    # Merge order (lowest → highest): defaults <- file <- stdin <- flags
    base: Dict[str, Any] = {}
    if args.file:
        base = deep_merge(base, load_spec_from_file(args.file))
    if args.read_stdin:
        base = deep_merge(base, load_spec_from_stdin())

    labels = parse_kv_pairs(args.label or [])
    metadata_cli = parse_kv_pairs(args.meta or [])

    cli: Dict[str, Any] = {
        "device_id": args.device_id,
        "model": args.model,
        "hw_revision": args.hw_revision,
        "serial": args.serial,
        "site": args.site,
        "public_key_ed25519": args.public_key,
    }
    if labels:
        cli["labels"] = labels
    if metadata_cli:
        cli["metadata"] = metadata_cli
    if args.twin:
        # try JSON first, then file path
        twin = None
        try:
            twin = json.loads(args.twin)
        except Exception:
            if os.path.isfile(args.twin):
                twin = load_spec_from_file(args.twin)
        if twin is None:
            raise ValueError("--twin must be JSON string or path to JSON/YAML")
        cli["twin"] = twin

    merged = deep_merge(base, {k: v for k, v in cli.items() if v is not None})
    spec = DeviceSpec(**merged)
    validate_spec(spec)
    return spec

# --------- Networking ---------

@dataclass
class Backoff:
    base: float = 0.2
    multiplier: float = 2.0
    max_delay: float = 20.0
    jitter: float = 0.2
    max_attempts: int = 6

    def delay(self, attempt: int) -> float:
        attempt = max(1, attempt)
        expo = self.base * (self.multiplier ** (attempt - 1))
        d = min(expo, self.max_delay)
        j = d * self.jitter * ((os.urandom(1)[0] / 255.0) * 2 - 1)  # centered jitter
        return max(0.0, d + j)

def build_ssl_context(args: argparse.Namespace) -> ssl.SSLContext:
    if args.insecure:
        ctx = ssl._create_unverified_context()
    else:
        ctx = ssl.create_default_context(cafile=args.cacert if args.cacert else None)
    if args.cert and args.key:
        ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    return ctx

def build_opener(args: argparse.Namespace, ctx: ssl.SSLContext) -> urllib.request.OpenerDirector:
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if args.no_proxy:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)

def make_request(
    url: str,
    payload: Dict[str, Any],
    args: argparse.Namespace,
    opener: urllib.request.OpenerDirector,
    method: str = "POST",
) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url=url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", args.user_agent)
    idem = args.idempotency_key or str(uuid.uuid4())
    req.add_header("Idempotency-Key", idem)
    for h in args.header or []:
        if ":" not in h:
            raise ValueError(f"Invalid header: {h}")
        k, v = h.split(":", 1)
        req.add_header(k.strip(), v.strip())
    token = args.token or os.environ.get("PIC_TOKEN") or ""
    if token:
        if token.lower().startswith("bearer "):
            req.add_header("Authorization", token)
        else:
            req.add_header("Authorization", f"Bearer {token}")

    try:
        with opener.open(req, timeout=args.timeout) as resp:
            body = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            parsed = {}
            if "application/json" in ctype:
                parsed = json.loads(body.decode("utf-8") or "{}")
            else:
                parsed = {"raw": body.decode("utf-8", "replace")}
            headers = {k: v for k, v in resp.headers.items()}
            return resp.getcode(), parsed, headers
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            parsed = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            parsed = {"error": body.decode("utf-8", "replace")}
        headers = {k: v for k, v in e.headers.items()} if e.headers else {}
        return e.code, parsed, headers
    except urllib.error.URLError as e:
        raise ConnectionError(str(e)) from e

def request_with_retries(
    url: str,
    payload: Dict[str, Any],
    args: argparse.Namespace,
    opener: urllib.request.OpenerDirector,
    primary_method: str,
    upsert_url: Optional[str],
    backoff: Backoff,
) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    attempt = 1
    while True:
        code, parsed, headers = make_request(url, payload, args, opener, method=primary_method)
        # Upsert fallback: on 409/404 switch to PUT if upsert_url specified
        if upsert_url and code in (404, 409) and primary_method != "PUT":
            code, parsed, headers = make_request(upsert_url, payload, args, opener, method="PUT")

        if code >= 200 and code < 300:
            return code, parsed, headers

        if attempt >= backoff.max_attempts:
            return code, parsed, headers

        transient = code in (408, 425, 429, 500, 502, 503, 504)
        if not transient:
            return code, parsed, headers

        delay = backoff.delay(attempt)
        eprint(f"[retry] attempt {attempt} code={code} waiting {delay:.2f}s")
        time.sleep(delay)
        attempt += 1

# --------- Curl helper ---------

def as_curl(url: str, payload: Dict[str, Any], args: argparse.Namespace) -> str:
    parts = ["curl", "-sS", "-X", "POST", "--connect-timeout", str(args.timeout)]
    if args.insecure:
        parts.append("-k")
    if args.cacert:
        parts += ["--cacert", shlex_quote(args.cacert)]
    if args.cert and args.key:
        parts += ["--cert", shlex_quote(args.cert), "--key", shlex_quote(args.key)]
    token = args.token or os.environ.get("PIC_TOKEN") or ""
    if token:
        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        parts += ["-H", shlex_quote(f"Authorization: {token}")]
    for h in args.header or []:
        parts += ["-H", shlex_quote(h)]
    parts += ["-H", "Content-Type: application/json", "-H", "Accept: application/json"]
    idem = args.idempotency_key or "<generated>"
    parts += ["-H", shlex_quote(f"Idempotency-Key: {idem}")]
    parts += ["--data", shlex_quote(json.dumps(payload))]
    parts.append(shlex_quote(url))
    return " ".join(parts)

def shlex_quote(s: str) -> str:
    # simple portable quoting without importing shlex (Windows safe)
    if not s or re.search(r"\s|['\"\\]", s):
        return "'" + s.replace("'", "'\"'\"'") + "'"
    return s

# --------- Key generation (optional) ---------

def maybe_generate_keypair(args: argparse.Namespace) -> Optional[str]:
    if not args.gen_key:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore
        from cryptography.hazmat.primitives import serialization  # type: ignore
    except Exception:
        raise RuntimeError("--gen-key requires 'cryptography' package")
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                      format=serialization.PublicFormat.Raw)
    # Save if requested
    if args.gen_key_priv:
        pem = sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(args.gen_key_priv, "wb") as f:
            f.write(pem)
    if args.gen_key_pub:
        with open(args.gen_key_pub, "w", encoding="utf-8") as f:
            f.write(pk.hex())
    return pk.hex()

# --------- CLI ---------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="register_device",
        description="Register/Upsert device in backend via HTTPS.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Input
    p.add_argument("--file", help="Device spec JSON/YAML file")
    p.add_argument("--read-stdin", action="store_true", help="Read spec from STDIN (JSON or YAML if PyYAML installed)")
    p.add_argument("--device-id", help="Device ID (if omitted, derived from fingerprint)")
    p.add_argument("--model", help="Device model (required if not provided in spec)")
    p.add_argument("--hw-revision", help="Hardware revision")
    p.add_argument("--serial", help="Serial number")
    p.add_argument("--site", help="Site/location")
    p.add_argument("--label", action="append", help="Label key=value (repeatable)")
    p.add_argument("--meta", action="append", help="Metadata key=value (repeatable)")
    p.add_argument("--twin", help="Initial twin JSON string or path to JSON/YAML file")
    p.add_argument("--public-key", help="Ed25519 public key (hex or base64)")

    # Optional keypair generation
    p.add_argument("--gen-key", action="store_true", help="Generate Ed25519 keypair and include public key")
    p.add_argument("--gen-key-priv", help="Path to write private key PEM")
    p.add_argument("--gen-key-pub", help="Path to write public key hex")

    # Network/API
    p.add_argument("--api-base", default=os.environ.get("PIC_API_BASE", ""), help="API base URL, e.g. https://host")
    p.add_argument("--path", default="/v1/devices", help="Registration path for POST")
    p.add_argument("--upsert-path-template", default="/v1/devices/{device_id}", help="PUT path template for upsert (used on 404/409)")
    p.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout seconds")
    p.add_argument("--header", action="append", help="Additional header 'Name: Value' (repeatable)")
    p.add_argument("--token", help="Bearer token (or set PIC_TOKEN env)")
    p.add_argument("--cacert", help="Custom CA bundle (PEM)")
    p.add_argument("--cert", help="Client certificate (PEM) for mTLS")
    p.add_argument("--key", help="Client private key (PEM) for mTLS")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification (NOT recommended)")
    p.add_argument("--no-proxy", action="store_true", help="Ignore system proxy settings")
    p.add_argument("--user-agent", default="pic-cli/1.0 register_device", help="HTTP User-Agent")
    p.add_argument("--idempotency-key", help="Explicit Idempotency-Key header value")

    # Behavior
    p.add_argument("--retries", type=int, default=5, help="Max retry attempts for transient HTTP errors")
    p.add_argument("--retry-base", type=float, default=0.2, help="Base backoff seconds")
    p.add_argument("--retry-multiplier", type=float, default=2.0, help="Backoff multiplier")
    p.add_argument("--retry-max", type=float, default=20.0, help="Max backoff seconds")
    p.add_argument("--retry-jitter", type=float, default=0.2, help="Centered jitter fraction [0..1]")
    p.add_argument("--dry-run", action="store_true", help="Print payload and exit without network calls")
    p.add_argument("--print-curl", action="store_true", help="Print equivalent curl command")
    p.add_argument("--unverified-output", action="store_true",
                   help="Mark output with 'I cannot verify this.' banner for pipelines requiring explicit labeling")
    return p

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # Optional key generation
    try:
        pk_hex = maybe_generate_keypair(args)
        if pk_hex and not args.public_key:
            args.public_key = pk_hex
    except Exception as e:
        print_json_error("key_generation_error", str(e), 2, args)
        return 2

    # Build spec
    try:
        spec = build_spec(args)
    except Exception as e:
        print_json_error("validation_error", str(e), 2, args)
        return 2

    payload = spec.to_payload()
    url = join_url(args.api_base, args.path)
    upsert_url = None
    if args.upsert_path_template:
        upsert_url = join_url(args.api_base, args.upsert_path_template.format(device_id=spec.device_id))

    if args.dry_run:
        out = {"dry_run": True, "url": url, "upsert_url": upsert_url, "payload": payload}
        if args.unverified_output:
            out["note"] = "I cannot verify this."
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0

    # SSL + opener
    try:
        ctx = build_ssl_context(args)
        opener = build_opener(args, ctx)
    except Exception as e:
        print_json_error("tls_error", str(e), 3, args)
        return 3

    if args.print_curl:
        print(as_curl(url, payload, args))

    backoff = Backoff(
        base=args.retry_base,
        multiplier=args.retry_multiplier,
        max_delay=args.retry_max,
        jitter=args.retry_jitter,
        max_attempts=max(1, args.retries),
    )

    try:
        code, parsed, headers = request_with_retries(
            url=url,
            payload=payload,
            args=args,
            opener=opener,
            primary_method="POST",
            upsert_url=upsert_url,
            backoff=backoff,
        )
    except ConnectionError as e:
        print_json_error("network_error", str(e), 4, args)
        return 4
    except Exception as e:
        print_json_error("unexpected_error", str(e), 5, args)
        return 5

    out = {
        "status": code,
        "ok": 200 <= code < 300,
        "response": parsed,
        "headers": headers,
        "request_id": headers.get("X-Request-ID") if headers else None,
    }
    if args.unverified_output:
        out["note"] = "I cannot verify this."
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if 200 <= code < 300 else 1

def print_json_error(kind: str, message: str, exit_code: int, args: argparse.Namespace):
    out = {"ok": False, "error": {"kind": kind, "message": message}}
    if args and getattr(args, "unverified_output", False):
        out["note"] = "I cannot verify this."
    print(json.dumps(out, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    sys.exit(main())
