# physical-integration-core/cli/tools/inspect_twin.py
"""
CLI tool for inspecting a Digital Twin in physical-integration-core.

Features:
- Load Twin from JSON/YAML file, URL, or STDIN.
- Strict validation with Pydantic: unique IDs, endpoint URL format, referential integrity.
- Health checks: HTTP GET {endpoint}/health with timeout & concurrency.
- Diff with live inventory (file/URL) and firmware drift analysis (target vs current).
- Export in normalized JSON or Graphviz DOT (device graph).
- Safe filtering (--filter key=value, --contains key=sub) without eval.
- Structured logging; deterministic hashing of Twin for provenance.
- Optional integrations:
    * httpx       (HTTP fetch and health checks; falls back gracefully if unavailable)
    * PyYAML      (YAML parsing)
    * rich        (pretty tables)
    * Policy Core adapter (if installed at physical_integration.adapters.policy_core_adapter)

Exit codes:
    0 OK
    1 Validation errors
    2 Drift found (firmware or diff mismatch)
    3 Connectivity failures (ping)
    4 Policy denied / policy check failed
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

# Optional deps
try:
    import httpx  # type: ignore
    _HTTPX = True
except Exception:
    _HTTPX = False

try:
    import yaml  # type: ignore
    _YAML = True
except Exception:
    _YAML = False

try:
    from rich import box  # type: ignore
    from rich.console import Console  # type: ignore
    from rich.table import Table  # type: ignore
    _RICH = True
    _console = Console(stderr=False)
except Exception:
    _RICH = False
    _console = None

# Pydantic
try:
    from pydantic import BaseModel, Field, validator, root_validator
except Exception as e:
    raise RuntimeError("pydantic>=1.10 is required for inspect_twin") from e


# ----------------------------- Logging ----------------------------------------

def _configure_logger() -> logging.Logger:
    lvl = os.environ.get("INSPECT_TWIN_LOG_LEVEL", "INFO").upper()
    logger = logging.getLogger("cli.inspect_twin")
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        fmt = logging.Formatter("%(asctime)sZ %(levelname)s %(name)s %(message)s", "%Y-%m-%dT%H:%M:%S")
        h.setFormatter(fmt)
        logger.addHandler(h)
        logger.propagate = False
    logger.setLevel(getattr(logging, lvl, logging.INFO))
    return logger

log = _configure_logger()

def _truncate(s: str, n: int = 400) -> str:
    return s if len(s) <= n else s[:n] + "...[truncated]"

def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


# ----------------------------- Models -----------------------------------------

class Link(BaseModel):
    # Optional directed edge between devices (e.g., upstream/downstream)
    src: str
    dst: str
    kind: Optional[str] = None  # e.g., "rtsp", "control", "power"

class DeviceTwin(BaseModel):
    id: str
    type: str = Field(default="device")
    model: Optional[str] = None
    group: Optional[str] = None
    endpoint: Optional[str] = None  # base URL like http://host:port
    tags: Dict[str, str] = Field(default_factory=dict)
    desired_firmware_version: Optional[str] = None
    current_firmware_version: Optional[str] = None  # optional snapshot in twin
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator("endpoint")
    def _validate_endpoint(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return v
        # Minimal format check
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("endpoint must start with http:// or https://")
        return v

class TwinDocument(BaseModel):
    version: str = "1.0"
    site: Optional[str] = None
    devices: List[DeviceTwin] = Field(default_factory=list)
    links: List[Link] = Field(default_factory=list)
    meta: Dict[str, Any] = Field(default_factory=dict)
    checksum: Optional[str] = None  # deterministic content hash

    @root_validator
    def _unique_ids(cls, values):
        ids = [d.id for d in values.get("devices", [])]
        if len(ids) != len(set(ids)):
            dupes = [i for i in ids if ids.count(i) > 1]
            raise ValueError(f"duplicate device ids: {sorted(set(dupes))}")
        # link referential integrity
        known = set(ids)
        bad = []
        for l in values.get("links", []):
            if l.src not in known or l.dst not in known:
                bad.append((l.src, l.dst))
        if bad:
            raise ValueError(f"links reference unknown devices: {bad}")
        return values

    @validator("checksum", always=True, pre=True)
    def _auto_checksum(cls, v, values):
        if v:
            return v
        snap = {
            "version": values.get("version"),
            "site": values.get("site"),
            "devices": [d.dict() for d in values.get("devices", [])],
            "links": [l.dict() for l in values.get("links", [])],
            "meta": values.get("meta", {}),
        }
        b = json.dumps(snap, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(b).hexdigest()


# ----------------------------- I/O helpers ------------------------------------

def _read_stdin() -> str:
    return sys.stdin.read()

def _load_from_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def _fetch_url(url: str, timeout: float = 8.0) -> str:
    if not _HTTPX:
        raise RuntimeError("httpx is not installed; cannot fetch URL")
    r = httpx.get(url, timeout=timeout, follow_redirects=True)
    r.raise_for_status()
    return r.text

def _parse_payload(payload: str) -> Dict[str, Any]:
    s = payload.strip()
    if not s:
        raise ValueError("empty input")
    # Try JSON first
    if s.startswith("{") or s.startswith("["):
        return json.loads(s)
    # Then YAML if available
    if _YAML:
        return yaml.safe_load(s)
    # Fallback: try JSON again to raise a clear error
    return json.loads(s)

def _load_twin(source: Optional[str]) -> TwinDocument:
    """
    source: path or URL; if None or '-', read from STDIN.
    """
    if source in (None, "-"):
        raw = _read_stdin()
    elif source.startswith("http://") or source.startswith("https://"):
        raw = _fetch_url(source)
    else:
        raw = _load_from_file(source)
    data = _parse_payload(raw)
    return TwinDocument(**data)

def _load_inventory(source: str) -> Dict[str, Dict[str, Any]]:
    """
    Inventory schema (flexible): dict with keys as device_id or list of devices.
    We normalize into {id: {...}}.
    """
    if source.startswith("http://") or source.startswith("https://"):
        raw = _fetch_url(source)
    else:
        raw = _load_from_file(source)
    data = _parse_payload(raw)
    if isinstance(data, dict) and "devices" in data and isinstance(data["devices"], list):
        data = {d.get("id"): d for d in data["devices"] if "id" in d}
    if isinstance(data, list):
        data = {d.get("id"): d for d in data if isinstance(d, dict) and "id" in d}
    if not isinstance(data, dict):
        raise ValueError("inventory must be a dict or list with device objects")
    return data


# ----------------------------- Filters ----------------------------------------

def _apply_filters(devs: List[DeviceTwin], equals: List[str], contains: List[str]) -> List[DeviceTwin]:
    """
    equals: ["key=value", ...], contains: ["key=sub", ...]
    Supported keys: id, type, model, group, endpoint, tags.<k>, metadata.<k>
    """
    def get_val(d: DeviceTwin, key: str) -> Optional[str]:
        if key.startswith("tags."):
            return d.tags.get(key[5:])
        if key.startswith("metadata."):
            v = d.metadata.get(key[9:])
            return str(v) if v is not None else None
        return getattr(d, key, None)

    out = []
    for d in devs:
        ok = True
        for expr in equals:
            if "=" not in expr:
                continue
            k, v = expr.split("=", 1)
            if (get_val(d, k) or "") != v:
                ok = False
                break
        if not ok:
            continue
        for expr in contains:
            if "=" not in expr:
                continue
            k, sub = expr.split("=", 1)
            if sub not in (get_val(d, k) or ""):
                ok = False
                break
        if ok:
            out.append(d)
    return out


# ----------------------------- Printers ---------------------------------------

def _print_table(rows: List[Dict[str, Any]], title: str = "Devices") -> None:
    if _RICH:
        table = Table(title=title, box=box.SIMPLE, show_lines=False)
        if not rows:
            _console.print("[dim]no rows[/dim]")
            return
        cols = list(rows[0].keys())
        for c in cols:
            table.add_column(c)
        for r in rows:
            table.add_row(*[str(r.get(c, "")) for c in cols])
        _console.print(table)
    else:
        # plain
        if not rows:
            print("no rows")
            return
        cols = list(rows[0].keys())
        print("\t".join(cols))
        for r in rows:
            print("\t".join(str(r.get(c, "")) for c in cols))


# ----------------------------- Health checks ----------------------------------

def _health_check(endpoint: str, timeout: float = 5.0) -> Tuple[bool, str, Optional[str]]:
    """
    Returns (ok, reason, version) for GET {endpoint}/health
    """
    if not endpoint:
        return False, "no endpoint", None
    if not _HTTPX:
        return False, "httpx not installed", None
    try:
        r = httpx.get(f"{endpoint.rstrip('/')}/health", timeout=timeout)
        if r.status_code != 200:
            return False, f"http {r.status_code}", None
        j = r.json()
        ok = bool(j.get("ok", True))
        ver = j.get("version")
        return ok, "ok" if ok else j.get("reason", "not ok"), ver
    except Exception as e:
        return False, f"error {e!r}", None


# ----------------------------- Policy Core ------------------------------------

def _policy_check(subject_id: str, roles: List[str], device: DeviceTwin, action: str) -> Tuple[bool, str]:
    """
    Integrates with Policy Core adapter if available.
    """
    try:
        from physical_integration.adapters.policy_core_adapter import (
            PolicyAdapterSettings, PolicyCoreAdapter,
            Subject, Resource, Action, Context
        )
    except Exception:
        return False, "Policy adapter not available"

    async def _run() -> Tuple[bool, str]:
        settings = PolicyAdapterSettings(
            pdp_base_url=os.environ.get("POLICY_PDP_BASE_URL", "http://127.0.0.1:8080"),
            pdp_decide_path=os.environ.get("POLICY_PDP_DECIDE_PATH", "/v1/decision"),
            jwt_hs256_secret=os.environ.get("POLICY_JWT_HS256_SECRET"),
            metrics_port=int(os.environ.get("METRICS_PORT", "0") or 0) or None,
        )
        adapter = PolicyCoreAdapter(settings=settings)
        await adapter.start()
        try:
            subj = Subject(id=subject_id, roles=roles)
            res = Resource(id=device.id, type=device.type or "device", attrs={"model": device.model or "", "group": device.group or ""})
            act = Action(name=action.upper())
            ctx = Context()
            dec = await adapter.check_access(subj, res, act, ctx)
            return (dec.effect == "Permit", dec.reason or "no-reason")
        finally:
            await adapter.close()

    import asyncio
    return asyncio.run(_run())


# ----------------------------- Commands ---------------------------------------

def cmd_summary(twin: TwinDocument, args: argparse.Namespace) -> int:
    rows = []
    for d in _apply_filters(twin.devices, args.filter or [], args.contains or []):
        rows.append({
            "id": d.id,
            "type": d.type,
            "model": d.model or "",
            "group": d.group or "",
            "endpoint": d.endpoint or "",
            "desired_fw": d.desired_firmware_version or "",
            "current_fw": d.current_firmware_version or "",
        })
    _print_table(rows, title=f"Devices (site={twin.site or '-'}, items={len(rows)})")
    print(json.dumps({"checksum": twin.checksum, "site": twin.site, "version": twin.version}, ensure_ascii=False))
    return 0

def cmd_validate(twin: TwinDocument, _: argparse.Namespace) -> int:
    # Root validators already ran. Add extra checks if needed.
    problems: List[str] = []
    for d in twin.devices:
        if d.endpoint and (" " in d.endpoint or d.endpoint.endswith("/")):
            problems.append(f"{d.id}: malformed endpoint '{d.endpoint}'")
    if problems:
        for p in problems:
            log.error("validation", extra={"problem": p})
        print(json.dumps({"status": "invalid", "problems": problems}, ensure_ascii=False))
        return 1
    print(json.dumps({"status": "ok", "devices": len(twin.devices), "checksum": twin.checksum}, ensure_ascii=False))
    return 0

def cmd_ping(twin: TwinDocument, args: argparse.Namespace) -> int:
    if not _HTTPX:
        print(json.dumps({"status": "error", "reason": "httpx not installed"}, ensure_ascii=False))
        return 3
    to_check = [d for d in _apply_filters(twin.devices, args.filter or [], args.contains or []) if d.endpoint]
    ok = 0
    fail = 0
    rows = []
    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as tp:
        futures = {tp.submit(_health_check, d.endpoint, args.timeout): d for d in to_check}
        for fut, dev in futures.items():
            try:
                res_ok, reason, ver = fut.result()
            except Exception as e:
                res_ok, reason, ver = False, f"exec {e!r}", None
            rows.append({"id": dev.id, "ok": res_ok, "reason": reason, "version": ver or ""})
            ok += 1 if res_ok else 0
            fail += 0 if res_ok else 1
    _print_table(rows, title=f"Health ({ok} ok, {fail} fail)")
    return 0 if fail == 0 else 3

def cmd_diff(twin: TwinDocument, args: argparse.Namespace) -> int:
    inv = _load_inventory(args.inventory)
    diffs: List[Dict[str, Any]] = []
    for d in _apply_filters(twin.devices, args.filter or [], args.contains or []):
        live = inv.get(d.id, {})
        # Compare endpoint and firmware
        ep_live = live.get("endpoint")
        fw_live = live.get("current_version") or live.get("firmware") or live.get("current_firmware_version")
        # Endpoint drift if both are known and differ
        if d.endpoint and ep_live and d.endpoint != ep_live:
            diffs.append({"id": d.id, "field": "endpoint", "twin": d.endpoint, "live": ep_live})
        # Firmware drift
        if d.desired_firmware_version and fw_live and d.desired_firmware_version != fw_live:
            diffs.append({"id": d.id, "field": "firmware", "desired": d.desired_firmware_version, "current": fw_live})
    _print_table(diffs or [{"id": "-", "field": "-", "twin": "-", "live": "-"}], title="Diff")
    return 0 if not diffs else 2

def cmd_firmware_drift(twin: TwinDocument, args: argparse.Namespace) -> int:
    inv = _load_inventory(args.inventory) if args.inventory else None
    rows = []
    drift = 0
    for d in _apply_filters(twin.devices, args.filter or [], args.contains or []):
        target = d.desired_firmware_version
        current = d.current_firmware_version
        if inv is not None and d.id in inv:
            current = inv[d.id].get("current_version") or inv[d.id].get("firmware") or current
        if target and current and target != current:
            drift += 1
            rows.append({"id": d.id, "target": target, "current": current})
    _print_table(rows or [{"id": "-", "target": "-", "current": "-"}], title="Firmware drift")
    return 0 if drift == 0 else 2

def cmd_export(twin: TwinDocument, args: argparse.Namespace) -> int:
    if args.format == "json":
        out = json.dumps(twin.dict(), ensure_ascii=False, indent=2)
    elif args.format == "dot":
        # Graphviz DOT (devices as nodes, links as edges)
        lines = ["digraph twin {", '  rankdir=LR;']
        for d in twin.devices:
            label = f"{d.id}\\n{d.model or ''}"
            lines.append(f'  "{d.id}" [shape=box,label="{label}"];')
        for l in twin.links:
            attr = f' [label="{l.kind}"]' if l.kind else ""
            lines.append(f'  "{l.src}" -> "{l.dst}"{attr};')
        lines.append("}")
        out = "\n".join(lines)
    else:
        print(json.dumps({"status": "error", "reason": "unknown format"}, ensure_ascii=False))
        return 1
    if args.out and args.out != "-":
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(json.dumps({"status": "ok", "path": args.out, "format": args.format}, ensure_ascii=False))
    else:
        print(out)
    return 0

def cmd_policy(twin: TwinDocument, args: argparse.Namespace) -> int:
    dev = next((d for d in twin.devices if d.id == args.device_id), None)
    if not dev:
        print(json.dumps({"status": "error", "reason": "device not found"}, ensure_ascii=False))
        return 1
    ok, reason = _policy_check(args.subject_id, args.roles or [], dev, args.action)
    result = {"device": dev.id, "action": args.action, "permit": ok, "reason": reason}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if ok else 4


# ----------------------------- CLI parsing ------------------------------------

def _add_common_filters(p: argparse.ArgumentParser) -> None:
    p.add_argument("--filter", action="append", help="Exact match filter key=value (e.g., model=X1)", default=[])
    p.add_argument("--contains", action="append", help="Substring filter key=sub (e.g., id=cam-)", default=[])

def make_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="inspect_twin", description="Inspect and validate Digital Twin")
    ap.add_argument("--source", "-s", help="Twin source: file path, URL, or '-' for STDIN", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_sum = sub.add_parser("summary", help="Show devices summary")
    _add_common_filters(p_sum)

    p_val = sub.add_parser("validate", help="Validate twin document")

    p_ping = sub.add_parser("ping", help="Ping device /health")
    p_ping.add_argument("--timeout", type=float, default=5.0)
    p_ping.add_argument("--concurrency", type=int, default=16)
    _add_common_filters(p_ping)

    p_diff = sub.add_parser("diff", help="Diff with live inventory (file/URL)")
    p_diff.add_argument("--inventory", "-i", required=True, help="Inventory file or URL")
    _add_common_filters(p_diff)

    p_fw = sub.add_parser("firmware-drift", help="Check firmware drift vs inventory or embedded twin current")
    p_fw.add_argument("--inventory", "-i", required=False, help="Optional inventory file or URL")
    _add_common_filters(p_fw)

    p_exp = sub.add_parser("export", help="Export twin (json|dot)")
    p_exp.add_argument("--format", "-f", choices=["json", "dot"], default="json")
    p_exp.add_argument("--out", "-o", help="Output file or '-' for stdout", default="-")

    p_pol = sub.add_parser("policy", help="Check access decision via Policy Core")
    p_pol.add_argument("--device-id", required=True)
    p_pol.add_argument("--subject-id", required=True)
    p_pol.add_argument("--roles", nargs="*", default=[])
    p_pol.add_argument("--action", choices=["read", "write", "delete"], default="read")

    return ap

def main(argv: Optional[List[str]] = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)

    try:
        twin = _load_twin(args.source)  # may raise
    except Exception as e:
        log.error("failed to load twin", extra={"error": repr(e)})
        print(json.dumps({"status": "error", "reason": f"load: {e}"}, ensure_ascii=False))
        return 1

    if args.cmd == "summary":
        return cmd_summary(twin, args)
    if args.cmd == "validate":
        return cmd_validate(twin, args)
    if args.cmd == "ping":
        return cmd_ping(twin, args)
    if args.cmd == "diff":
        return cmd_diff(twin, args)
    if args.cmd == "firmware-drift":
        return cmd_firmware_drift(twin, args)
    if args.cmd == "export":
        return cmd_export(twin, args)
    if args.cmd == "policy":
        return cmd_policy(twin, args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
