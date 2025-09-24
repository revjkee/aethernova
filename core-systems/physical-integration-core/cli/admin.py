# physical-integration-core/cli/admin.py
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Внутренние утилиты идентификаторов
try:
    from physical_integration.utils.idgen import (
        MonotonicULID,
        uuid4_str,
        with_prefix,
        Snowflake,
        SnowflakeConfig,
    )
except Exception:
    # Позволяет запускать как скрипт из корня репозитория без установки пакета
    sys.path.append(str(Path(__file__).resolve().parents[1]))
    from physical_integration.utils.idgen import (  # type: ignore
        MonotonicULID,
        uuid4_str,
        with_prefix,
        Snowflake,
        SnowflakeConfig,
    )

DEFAULT_BASE_URL = "http://localhost:8080"
DEFAULT_TIMEOUT = 10.0
DEFAULT_CONFIG_PATH = Path.home() / ".picore" / "admin.json"


@dataclass
class Config:
    base_url: str = DEFAULT_BASE_URL
    token: Optional[str] = None
    api_key: Optional[str] = None
    timeout: float = DEFAULT_TIMEOUT

    @staticmethod
    def load(path: Optional[Path]) -> "Config":
        cfg = Config()
        # 1) файл
        p = path if path else DEFAULT_CONFIG_PATH
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                cfg.base_url = str(data.get("base_url", cfg.base_url))
                cfg.token = data.get("token", cfg.token)
                cfg.api_key = data.get("api_key", cfg.api_key)
                cfg.timeout = float(data.get("timeout", cfg.timeout))
            except Exception:
                pass
        # 2) окружение
        cfg.base_url = os.getenv("PICORE_BASE_URL", cfg.base_url)
        cfg.token = os.getenv("PICORE_TOKEN", cfg.token)
        cfg.api_key = os.getenv("PICORE_API_KEY", cfg.api_key)
        cfg.timeout = float(os.getenv("PICORE_TIMEOUT", cfg.timeout))
        return cfg

    def override(self, args: argparse.Namespace) -> "Config":
        c = Config(self.base_url, self.token, self.api_key, self.timeout)
        if getattr(args, "base_url", None):
            c.base_url = args.base_url
        if getattr(args, "token", None):
            c.token = args.token
        if getattr(args, "api_key", None):
            c.api_key = args.api_key
        if getattr(args, "timeout", None):
            c.timeout = float(args.timeout)
        return c


def _print(obj: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        if isinstance(obj, (dict, list)):
            print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False))
        else:
            print(str(obj))


def _headers(cfg: Config, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    h = {
        "User-Agent": "pi-core-admin/1.0",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if cfg.token:
        h["Authorization"] = f"Bearer {cfg.token}"
    if cfg.api_key:
        h["X-API-Key"] = cfg.api_key
    if extra:
        h.update(extra)
    return h


def _join(base: str, path: str) -> str:
    return urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _http_request(
    method: str,
    url: str,
    cfg: Config,
    payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    data: Optional[bytes] = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url=url, method=method.upper(), data=data, headers=_headers(cfg, headers))
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
            body = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            parsed: Dict[str, Any] = {}
            if "application/json" in ctype and body:
                parsed = json.loads(body.decode("utf-8"))
            return resp.getcode(), parsed, dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        err_body = e.read()
        parsed: Dict[str, Any] = {}
        try:
            parsed = json.loads(err_body.decode("utf-8"))
        except Exception:
            parsed = {"detail": err_body.decode("utf-8", errors="replace") or e.reason}
        return e.code, parsed, dict(e.headers.items() if e.headers else {})
    except urllib.error.URLError as e:
        raise SystemExit(f"Network error: {e.reason}") from e


# ------------------------- Команды CLI -------------------------

def cmd_ping(args: argparse.Namespace, cfg: Config) -> int:
    # Пытаемся /healthz, потом /readyz, затем /
    for path in ("/healthz", "/readyz", "/"):
        code, body, _ = _http_request("GET", _join(cfg.base_url, path), cfg)
        if code < 500:
            _print({"url": _join(cfg.base_url, path), "status": code, "body": body}, args.json)
            return 0 if code < 400 else 1
    _print({"error": "service unavailable"}, args.json)
    return 1


def _parse_constraints(s: Optional[str]) -> Dict[str, Any]:
    if not s:
        return {}
    try:
        val = json.loads(s)
        if isinstance(val, dict):
            return val
        raise ValueError("constraints must be a JSON object")
    except json.JSONDecodeError as e:
        raise SystemExit(f"Invalid JSON in --constraints: {e}") from e


def _parse_approvers(items: List[str]) -> List[Dict[str, str]]:
    # Форматы: "id", "id:name"
    out: List[Dict[str, str]] = []
    for it in items:
        if ":" in it:
            i, n = it.split(":", 1)
            out.append({"id": i.strip(), "name": n.strip()})
        else:
            out.append({"id": it.strip()})
    return out


def cmd_commands_execute(args: argparse.Namespace, cfg: Config) -> int:
    url = _join(cfg.base_url, "/api/v1/commands/execute")
    targets = [{"device_id": d} for d in args.device_id]
    params: Dict[str, Any] = {
        "image_id": args.image_id,
        "channel": args.channel,
        "constraints": _parse_constraints(args.constraints),
    }
    maintenance = None
    if args.maintenance_requested:
        maintenance = {
            "requested": True,
            "approvers": _parse_approvers(args.maintenance_approver or []),
            "approved_until": args.maintenance_until,
            "scope": _parse_constraints(args.maintenance_scope),
        }
    payload = {
        "command": args.command,
        "targets": targets,
        "params": {k: v for k, v in params.items() if v not in (None, {}, "")},
        "maintenance": maintenance,
    }
    idem = args.idempotency_key or str(uuid.uuid4())
    req_id = args.request_id or str(uuid.uuid4())
    code, body, _ = _http_request(
        "POST",
        url,
        cfg,
        payload=payload,
        headers={"Idempotency-Key": idem, "X-Request-ID": req_id},
    )
    _print({"status": code, "response": body}, args.json)
    return 0 if code < 400 else 1


def cmd_maintenance_approve(args: argparse.Namespace, cfg: Config) -> int:
    url = _join(cfg.base_url, "/api/v1/commands/maintenance/approve")
    targets = [{"device_id": d} for d in args.device_id]
    maintenance = {
        "requested": True,
        "approvers": _parse_approvers(args.approver or []),
        "approved_until": args.until,
        "scope": _parse_constraints(args.scope),
    }
    payload = {
        "command": "MAINTENANCE",
        "targets": targets,
        "maintenance": maintenance,
        "params": {},
    }
    idem = args.idempotency_key or str(uuid.uuid4())
    req_id = args.request_id or str(uuid.uuid4())
    code, body, _ = _http_request(
        "POST",
        url,
        cfg,
        payload=payload,
        headers={"Idempotency-Key": idem, "X-Request-ID": req_id},
    )
    _print({"status": code, "response": body}, args.json)
    return 0 if code < 400 else 1


def cmd_id_ulid(args: argparse.Namespace, cfg: Config) -> int:
    mono = MonotonicULID()
    items = []
    for _ in range(args.n):
        v = mono.generate()
        items.append(with_prefix(args.prefix, v) if args.prefix else v)
    _print(items if args.n > 1 else items[0], args.json)
    return 0


def cmd_id_uuid4(args: argparse.Namespace, cfg: Config) -> int:
    items = []
    for _ in range(args.n):
        v = uuid4_str()
        items.append(with_prefix(args.prefix, v) if args.prefix else v)
    _print(items if args.n > 1 else items[0], args.json)
    return 0


def cmd_id_snowflake(args: argparse.Namespace, cfg: Config) -> int:
    sf = Snowflake(node_id=args.node, cfg=SnowflakeConfig())
    items = []
    for _ in range(args.n):
        val = sf.next_base58() if args.base == "58" else sf.next_base62()
        items.append(with_prefix(args.prefix, val) if args.prefix else val)
    _print(items if args.n > 1 else items[0], args.json)
    return 0


# ------------------------- Парсер аргументов -------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pi-admin",
        description="Physical Integration Core Admin CLI",
    )
    p.add_argument("--config", type=Path, help=f"Path to config file (default: {DEFAULT_CONFIG_PATH})")
    p.add_argument("--base-url", help=f"Base URL (default: {DEFAULT_BASE_URL} or PICORE_BASE_URL)")
    p.add_argument("--token", help="Bearer token (or set PICORE_TOKEN)")
    p.add_argument("--api-key", help="API key (or set PICORE_API_KEY)")
    p.add_argument("--timeout", type=float, help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--json", action="store_true", help="Output JSON")

    sub = p.add_subparsers(dest="cmd", required=True)

    # ping
    sp = sub.add_parser("ping", help="Check service health")
    sp.set_defaults(func=cmd_ping)

    # commands execute
    se = sub.add_parser("commands", help="Commands operations")
    se_sub = se.add_subparsers(dest="subcmd", required=True)

    se_exec = se_sub.add_parser("execute", help="Execute device commands")
    se_exec.add_argument("--command", required=True,
                         choices=["START", "RESUME", "RUN", "SHUTDOWN", "MAINTENANCE", "OTA_ASSIGN", "OTA_CANCEL"])
    se_exec.add_argument("--device-id", action="append", required=True,
                         help="Device ID (UUID). Can be repeated")
    se_exec.add_argument("--image-id", help="OTA image id (UUID) for OTA_ASSIGN")
    se_exec.add_argument("--channel", help="OTA channel name for OTA_ASSIGN")
    se_exec.add_argument("--constraints", help="JSON object with targeting constraints")
    se_exec.add_argument("--maintenance-requested", action="store_true", help="Include maintenance block")
    se_exec.add_argument("--maintenance-approver", action="append",
                         help="Approver as 'id' or 'id:name'. Can be repeated")
    se_exec.add_argument("--maintenance-until", help="ISO datetime until which maintenance is approved")
    se_exec.add_argument("--maintenance-scope", help="JSON object with maintenance scope")
    se_exec.add_argument("--idempotency-key", help="Custom Idempotency-Key header")
    se_exec.add_argument("--request-id", help="Custom X-Request-ID header")
    se_exec.set_defaults(func=cmd_commands_execute)

    # maintenance approve
    sm = sub.add_parser("maintenance", help="Maintenance operations")
    sm_sub = sm.add_subparsers(dest="subcmd", required=True)

    sm_ap = sm_sub.add_parser("approve", help="Approve maintenance mode for devices (two-person rule)")
    sm_ap.add_argument("--device-id", action="append", required=True, help="Device ID (UUID). Can be repeated")
    sm_ap.add_argument("--approver", action="append", required=True, help="Approver as 'id' or 'id:name'")
    sm_ap.add_argument("--until", required=False, help="ISO datetime until which maintenance is approved")
    sm_ap.add_argument("--scope", help="JSON object with maintenance scope")
    sm_ap.add_argument("--idempotency-key", help="Custom Idempotency-Key header")
    sm_ap.add_argument("--request-id", help="Custom X-Request-ID header")
    sm_ap.set_defaults(func=cmd_maintenance_approve)

    # id
    sid = sub.add_parser("id", help="ID generation utilities")
    sid_sub = sid.add_subparsers(dest="subcmd", required=True)

    sid_ulid = sid_sub.add_parser("ulid", help="Generate ULID")
    sid_ulid.add_argument("-n", type=int, default=1, help="Number of IDs")
    sid_ulid.add_argument("--prefix", help="Prefix to prepend")
    sid_ulid.set_defaults(func=cmd_id_ulid)

    sid_uuid = sid_sub.add_parser("uuid4", help="Generate UUIDv4")
    sid_uuid.add_argument("-n", type=int, default=1, help="Number of IDs")
    sid_uuid.add_argument("--prefix", help="Prefix to prepend")
    sid_uuid.set_defaults(func=cmd_id_uuid4)

    sid_snow = sid_sub.add_parser("snowflake", help="Generate Snowflake-like short IDs")
    sid_snow.add_argument("--node", type=int, default=1, help="Node identifier (0..1023 by default cfg)")
    sid_snow.add_argument("-n", type=int, default=1, help="Number of IDs")
    sid_snow.add_argument("--base", choices=["58", "62"], default="58", help="Output alphabet base58 or base62")
    sid_snow.add_argument("--prefix", help="Prefix to prepend")
    sid_snow.set_defaults(func=cmd_id_snowflake)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = Config.load(getattr(args, "config", None)).override(args)

    # Валидация UUID для device-id, если заданы
    for attr in ("device_id",):
        if hasattr(args, attr) and getattr(args, attr):
            try:
                for d in getattr(args, attr):
                    uuid.UUID(d)
            except Exception as e:
                parser.error(f"Invalid UUID in --device-id: {e}")

    try:
        return args.func(args, cfg)  # type: ignore[attr-defined]
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
