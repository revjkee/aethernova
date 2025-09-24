# cybersecurity-core/cli/tools/run_edr_action.py
# -*- coding: utf-8 -*-
"""
Industrial-grade EDR Action Runner (async)

Features:
- Unified CLI to trigger EDR actions across providers via a simple registry
- Async concurrency with bounded semaphore
- Robust input validation (mutually exclusive target sources, required fields)
- Retries with exponential backoff + jitter
- Structured JSON logging and optional audit log to file (JSONL)
- Dry-run mode (no external calls)
- Idempotency-key generation for traceability
- Secrets masking in logs
- Graceful shutdown on SIGINT/SIGTERM
- Generic HTTP provider example (configurable), easy to extend with real EDR APIs

Usage examples:
  python run_edr_action.py run \
      --provider generic_http \
      --action isolate \
      --device-id 12345 --device-id 67890 \
      --http-base-url https://edr.example/api \
      --http-path /v1/actions \
      --token $EDR_TOKEN \
      --audit-log ./audit.jsonl \
      --max-concurrency 10 --retries 3 --timeout 20

  python run_edr_action.py run \
      --provider generic_http \
      --action scan \
      --input-file ./targets.txt \
      --http-base-url https://edr.example/api \
      --http-path /v1/actions \
      --token-file ./token.txt \
      --json-output

Targets file format (one per line, comments with '#'):
  device_id:abc123
  hostname:workstation-42
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import json
import logging
import os
import random
import re
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

try:
    import httpx  # type: ignore
except ImportError as exc:
    print("Missing dependency: httpx. Install with: pip install httpx", file=sys.stderr)
    raise

# ---------------------------
# Types & Constants
# ---------------------------

ActionType = Literal[
    "isolate",
    "release",
    "scan",
    "quarantine",
    "unquarantine",
    "kill_process",
    "delete_file",
    "restart",
    "custom",
]

JSONDict = Dict[str, Any]

VALID_ACTIONS: Tuple[ActionType, ...] = (
    "isolate",
    "release",
    "scan",
    "quarantine",
    "unquarantine",
    "kill_process",
    "delete_file",
    "restart",
    "custom",
)

TARGET_DEVICE_ID_RE = re.compile(r"^device_id:(?P<value>[\w\-\.:/]+)$", re.IGNORECASE)
TARGET_HOSTNAME_RE = re.compile(r"^hostname:(?P<value>[A-Za-z0-9\-\._]+)$", re.IGNORECASE)

DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 3
DEFAULT_MAX_CONCURRENCY = 8

# ---------------------------
# Utilities
# ---------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def mask_secret(value: Optional[str], show_tail: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= show_tail:
        return "*" * len(value)
    return "*" * (len(value) - show_tail) + value[-show_tail:]

def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

def load_token(token: Optional[str], token_file: Optional[str]) -> Optional[str]:
    if token:
        return token
    if token_file:
        with open(token_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    return None

def read_targets_from_file(path: str) -> List["DeviceRef"]:
    targets: List[DeviceRef] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            m1 = TARGET_DEVICE_ID_RE.match(raw)
            m2 = TARGET_HOSTNAME_RE.match(raw)
            if m1:
                targets.append(DeviceRef(device_id=m1.group("value")))
            elif m2:
                targets.append(DeviceRef(hostname=m2.group("value")))
            else:
                raise ValueError(f"Invalid target line: {raw!r}. Use 'device_id:<id>' or 'hostname:<name>'.")
    return targets

def expand_targets(device_ids: Sequence[str], hostnames: Sequence[str]) -> List["DeviceRef"]:
    res: List[DeviceRef] = []
    for d in device_ids:
        res.append(DeviceRef(device_id=d))
    for h in hostnames:
        res.append(DeviceRef(hostname=h))
    return res

def compute_idempotency_key(provider: str, action: str, target: "DeviceRef", extra: Optional[str] = None) -> str:
    base = f"{provider}|{action}|{target.identity()}|{extra or ''}"
    digest = hashlib.sha256(base.encode("utf-8")).hexdigest()
    return digest

# ---------------------------
# Data Models
# ---------------------------

@dataclass(frozen=True)
class DeviceRef:
    device_id: Optional[str] = None
    hostname: Optional[str] = None

    def identity(self) -> str:
        if self.device_id:
            return f"device_id:{self.device_id}"
        if self.hostname:
            return f"hostname:{self.hostname}"
        return "unknown"

    def to_json(self) -> JSONDict:
        return {"device_id": self.device_id, "hostname": self.hostname}

@dataclass
class ActionRequest:
    provider: str
    action: ActionType
    target: DeviceRef
    reason: Optional[str] = None
    note: Optional[str] = None
    idempotency_key: Optional[str] = None
    metadata: JSONDict = field(default_factory=dict)

    def to_json(self) -> JSONDict:
        return {
            "provider": self.provider,
            "action": self.action,
            "target": self.target.to_json(),
            "reason": self.reason,
            "note": self.note,
            "idempotency_key": self.idempotency_key,
            "metadata": self.metadata,
        }

@dataclass
class ActionResult:
    ok: bool
    request: ActionRequest
    status_code: Optional[int] = None
    error: Optional[str] = None
    response: Optional[JSONDict] = None
    started_at: str = field(default_factory=utc_now_iso)
    finished_at: str = field(default_factory=utc_now_iso)
    attempt: int = 0

    def to_json(self) -> JSONDict:
        return {
            "ok": self.ok,
            "status_code": self.status_code,
            "error": self.error,
            "response": self.response,
            "attempt": self.attempt,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "request": self.request.to_json(),
        }

# ---------------------------
# Provider Interface & Registry
# ---------------------------

class EDRProvider:
    name: str = "base"

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs

    async def perform_action(self, req: ActionRequest, *, timeout: float) -> ActionResult:
        raise NotImplementedError

_PROVIDER_REGISTRY: Dict[str, type[EDRProvider]] = {}

def register_provider(cls: type[EDRProvider]) -> type[EDRProvider]:
    _PROVIDER_REGISTRY[cls.name] = cls
    return cls

def get_provider(name: str) -> type[EDRProvider]:
    if name not in _PROVIDER_REGISTRY:
        raise KeyError(f"Unknown provider: {name}. Available: {', '.join(sorted(_PROVIDER_REGISTRY.keys()))}")
    return _PROVIDER_REGISTRY[name]

# ---------------------------
# Generic HTTP Provider (Example)
# ---------------------------

@register_provider
class GenericHTTPProvider(EDRProvider):
    """
    Generic HTTP provider for demo/adapter usage.

    Expected kwargs:
      - base_url: str (required)
      - path: str (required)  e.g., '/v1/actions'
      - token: Optional[str]  (Bearer)
      - headers: Optional[dict]
      - verify: bool = True
      - proxies: Optional[dict]
      - method: str = 'POST'

    Payload schema (example):
    {
      "action": "<action>",
      "target": {"device_id": "...", "hostname": "..."},
      "reason": "...",
      "note": "...",
      "idempotency_key": "...",
      "metadata": {...}
    }
    """
    name = "generic_http"

    async def perform_action(self, req: ActionRequest, *, timeout: float) -> ActionResult:
        started = utc_now_iso()
        base_url: str = self.kwargs["base_url"]
        path: str = self.kwargs["path"]
        token: Optional[str] = self.kwargs.get("token")
        headers: Dict[str, str] = dict(self.kwargs.get("headers") or {})
        method: str = str(self.kwargs.get("method") or "POST").upper()
        verify: bool = bool(self.kwargs.get("verify", True))
        proxies: Optional[Dict[str, str]] = self.kwargs.get("proxies")

        if token:
            headers.setdefault("Authorization", f"Bearer {token}")
        headers.setdefault("Content-Type", "application/json")

        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        payload = req.to_json()

        async with httpx.AsyncClient(timeout=timeout, verify=verify, proxies=proxies) as client:
            try:
                if method == "POST":
                    resp = await client.post(url, json=payload)
                elif method == "PUT":
                    resp = await client.put(url, json=payload)
                else:
                    resp = await client.request(method, url, json=payload)  # fallback

                ok = 200 <= resp.status_code < 300
                body: Optional[JSONDict]
                try:
                    body = resp.json()
                except Exception:
                    body = {"raw": resp.text}

                return ActionResult(
                    ok=ok,
                    request=req,
                    status_code=resp.status_code,
                    response=body,
                    started_at=started,
                    finished_at=utc_now_iso(),
                )
            except httpx.HTTPError as e:
                return ActionResult(
                    ok=False,
                    request=req,
                    status_code=None,
                    error=str(e),
                    response=None,
                    started_at=started,
                    finished_at=utc_now_iso(),
                )

# ---------------------------
# Backoff / Retry
# ---------------------------

async def retry_action(
    fn: Awaitable[ActionResult] | callable,
    *,
    retries: int,
    base_delay: float = 0.75,
    max_delay: float = 8.0,
) -> ActionResult:
    attempt = 0
    last_result: Optional[ActionResult] = None
    while True:
        attempt += 1
        if callable(fn):
            result: ActionResult = await fn()
        else:
            # If fn is an awaitable (already constructed)
            result = await fn  # type: ignore

        result.attempt = attempt

        if result.ok or attempt > retries:
            return result

        # Prepare next backoff
        sleep_s = min(max_delay, base_delay * (2 ** (attempt - 1)))
        # Add jitter 0..sleep_s/2
        sleep_s += random.random() * (sleep_s / 2)
        await asyncio.sleep(sleep_s)
        last_result = result

# ---------------------------
# Runner
# ---------------------------

class GracefulExit(Exception):
    pass

def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    def _handler() -> None:
        raise GracefulExit()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handler)
        except NotImplementedError:
            # On Windows, signals may not be supported the same way
            pass

async def run_actions(
    provider_name: str,
    provider_kwargs: Dict[str, Any],
    action: ActionType,
    targets: Sequence[DeviceRef],
    *,
    reason: Optional[str],
    note: Optional[str],
    idempotency_salt: Optional[str],
    dry_run: bool,
    max_concurrency: int,
    retries: int,
    timeout: float,
    audit_log: Optional[str],
    json_output: bool,
) -> int:
    ProviderCls = get_provider(provider_name)
    provider = ProviderCls(**provider_kwargs)

    # Audit log file handler
    audit_fp = open(audit_log, "a", encoding="utf-8") if audit_log else None

    sem = asyncio.Semaphore(max_concurrency)
    tasks: List[Awaitable[ActionResult]] = []

    async def _do_one(target: DeviceRef) -> ActionResult:
        async with sem:
            req = ActionRequest(
                provider=provider_name,
                action=action,
                target=target,
                reason=reason,
                note=note,
            )
            req.idempotency_key = compute_idempotency_key(provider_name, action, target, idempotency_salt)

            if dry_run:
                result = ActionResult(
                    ok=True,
                    request=req,
                    status_code=None,
                    response={"dry_run": True},
                    error=None,
                )
            else:
                async def _call() -> ActionResult:
                    return await provider.perform_action(req, timeout=timeout)

                result = await retry_action(_call, retries=retries)

            # Output & audit
            line = json_dumps(result.to_json())
            if json_output:
                print(line)
            else:
                # Human-readable single-line
                status = "OK" if result.ok else "FAIL"
                target_id = target.identity()
                sc = f"{result.status_code}" if result.status_code is not None else "-"
                err = result.error or "-"
                print(f"[{status}] action={action} target={target_id} status_code={sc} idemp={req.idempotency_key} error={err}")

            if audit_fp:
                audit_fp.write(line + "\n")
                audit_fp.flush()

            return result

    for t in targets:
        tasks.append(_do_one(t))

    try:
        results = await asyncio.gather(*tasks, return_exceptions=False)
    finally:
        if audit_fp:
            audit_fp.close()

    # Return non-zero if any failed
    return 0 if all(r.ok for r in results) else 2

# ---------------------------
# CLI
# ---------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_edr_action",
        description="Run EDR actions across providers (industrial async CLI).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # list-providers
    sp_list = sub.add_parser("list-providers", help="List available providers")
    sp_list.set_defaults(func=cmd_list_providers)

    # run
    sp_run = sub.add_parser("run", help="Execute EDR action")
    sp_run.add_argument("--provider", required=True, help="Provider name (e.g., generic_http)")

    sp_run.add_argument("--action", required=True, choices=VALID_ACTIONS, help="Action to perform")

    target = sp_run.add_argument_group("Targets")
    target.add_argument("--device-id", action="append", default=[], help="Device ID (repeatable)")
    target.add_argument("--hostname", action="append", default=[], help="Hostname (repeatable)")
    target.add_argument("--input-file", help="File with targets: 'device_id:<id>' or 'hostname:<name>' per line")

    meta = sp_run.add_argument_group("Metadata")
    meta.add_argument("--reason", help="Reason/context for action")
    meta.add_argument("--note", help="Additional note")
    meta.add_argument("--idempotency-salt", help="Extra salt for idempotency-key")

    execg = sp_run.add_argument_group("Execution")
    execg.add_argument("--dry-run", action="store_true", help="Do not call provider, simulate success")
    execg.add_argument("--max-concurrency", type=int, default=DEFAULT_MAX_CONCURRENCY, help="Max parallel actions")
    execg.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Retry attempts on failure")
    execg.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-call timeout seconds")

    outg = sp_run.add_argument_group("Output")
    outg.add_argument("--json-output", action="store_true", help="Print each result as JSON line")
    outg.add_argument("--audit-log", help="Path to JSONL audit log file")

    # Provider-specific (generic_http)
    httpg = sp_run.add_argument_group("generic_http provider")
    httpg.add_argument("--http-base-url", help="[generic_http] Base URL")
    httpg.add_argument("--http-path", help="[generic_http] Path to action endpoint, e.g. /v1/actions")
    httpg.add_argument("--token", help="[generic_http] Bearer token (dangerous in shell history)")
    httpg.add_argument("--token-file", help="[generic_http] File with Bearer token")
    httpg.add_argument("--http-header", action="append", default=[], help='[generic_http] Extra header "Key: Value" (repeatable)')
    httpg.add_argument("--http-method", default="POST", help='[generic_http] HTTP method (POST/PUT/...)')
    httpg.add_argument("--no-verify-tls", action="store_true", help="[generic_http] Disable TLS verification (NOT recommended)")
    httpg.add_argument("--http-proxy", help='[generic_http] HTTP proxy URL, e.g. "http://proxy:8080"')
    httpg.add_argument("--https-proxy", help='[generic_http] HTTPS proxy URL, e.g. "http://proxy:8443"')

    return p

def parse_headers(headers: Sequence[str]) -> Dict[str, str]:
    res: Dict[str, str] = {}
    for h in headers:
        if ":" not in h:
            raise ValueError(f"Invalid header (expect 'Key: Value'): {h!r}")
        k, v = h.split(":", 1)
        res[k.strip()] = v.strip()
    return res

def validate_run_args(args: argparse.Namespace) -> Tuple[List[DeviceRef], Dict[str, Any]]:
    # Targets
    any_cli_targets = bool(args.device_id or args.hostname)
    if args.input_file and any_cli_targets:
        raise ValueError("Use either --input-file OR (--device-id/--hostname), not both.")
    if not args.input_file and not any_cli_targets:
        raise ValueError("Provide targets via --input-file or --device-id/--hostname.")
    if args.input_file:
        targets = read_targets_from_file(args.input_file)
    else:
        targets = expand_targets(args.device_id, args.hostname)

    if not targets:
        raise ValueError("No targets after parsing.")

    # Provider kwargs
    provider_kwargs: Dict[str, Any] = {}
    if args.provider == "generic_http":
        base_url = args.http_base_url
        path = args.http_path
        if not base_url or not path:
            raise ValueError("[generic_http] --http-base-url and --http-path are required.")
        token = load_token(args.token, args.token_file)
        headers = parse_headers(args.http_header)
        verify = not args.no_verify_tls
        proxies = {}
        if args.http_proxy:
            proxies["http://"] = args.http_proxy
        if args.https_proxy:
            proxies["https://"] = args.https_proxy
        provider_kwargs = {
            "base_url": base_url,
            "path": path,
            "token": token,
            "headers": headers,
            "verify": verify,
            "proxies": proxies or None,
            "method": args.http_method,
        }
    # Additional providers can be added here with elif ...

    return targets, provider_kwargs

def cmd_list_providers(args: argparse.Namespace) -> int:
    for name in sorted(_PROVIDER_REGISTRY.keys()):
        print(name)
    return 0

def cmd_run(args: argparse.Namespace) -> int:
    try:
        targets, provider_kwargs = validate_run_args(args)
    except Exception as e:
        print(f"Argument error: {e}", file=sys.stderr)
        return 3

    # Minimal redaction in logs
    token = provider_kwargs.get("token")
    if token:
        redacted = mask_secret(token)
        provider_kwargs["token"] = token  # keep real for runtime
        logging.getLogger(__name__).debug("Using token: %s", redacted)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _install_signal_handlers(loop)

    try:
        rc = loop.run_until_complete(
            run_actions(
                provider_name=args.provider,
                provider_kwargs=provider_kwargs,
                action=args.action,
                targets=targets,
                reason=args.reason,
                note=args.note,
                idempotency_salt=args.idempotency_salt,
                dry_run=args.dry_run,
                max_concurrency=args.max_concurrency,
                retries=args.retries,
                timeout=args.timeout,
                audit_log=args.audit_log,
                json_output=args.json_output,
            )
        )
        return rc
    except GracefulExit:
        print("Interrupted. Shutting down gracefully.", file=sys.stderr)
        return 130
    finally:
        try:
            loop.run_until_complete(asyncio.sleep(0))
        finally:
            loop.close()

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "list-providers":
        return cmd_list_providers(args)
    if args.command == "run":
        return cmd_run(args)
    parser.print_help()
    return 1

if __name__ == "__main__":
    # Structured logging setup (stdout only for CLI; external systems can wrap this)
    logging.basicConfig(
        level=os.environ.get("RUN_EDR_LOGLEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    sys.exit(main())
