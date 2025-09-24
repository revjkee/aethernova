# core-systems/avm_core/engine/cli/avmctl.py
# Aethernova AVM Control CLI (industrial-grade)
# Stdlib + requests only. No new external deps required.
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import getpass
import pathlib
import typing as t
from dataclasses import dataclass

import requests

DEFAULT_BASE_URL = os.getenv("AVMCTL_BASE_URL", "http://127.0.0.1:8080")
DEFAULT_TIMEOUT = float(os.getenv("AVMCTL_TIMEOUT_S", "5.0"))
DEFAULT_RETRIES = int(os.getenv("AVMCTL_RETRIES", "3"))
DEFAULT_CA_CERT = os.getenv("AVMCTL_CA_CERT", "")           # path to CA bundle
DEFAULT_CLIENT_CERT = os.getenv("AVMCTL_CLIENT_CERT", "")   # path to client cert (PEM)
DEFAULT_CLIENT_KEY = os.getenv("AVMCTL_CLIENT_KEY", "")     # path to client key (PEM)
DEFAULT_TOKEN = os.getenv("AVMCTL_TOKEN", "")               # raw token or "file:/path"
DEFAULT_CONFIG = os.getenv("AVMCTL_CONFIG", str(pathlib.Path.home() / ".config" / "aethernova" / "avmctl.yaml"))

EXIT_OK = 0
EXIT_BAD_REQUEST = 1
EXIT_FORBIDDEN = 3
EXIT_NOT_FOUND = 4
EXIT_SERVER_ERROR = 5
EXIT_NET_ERROR = 7
EXIT_INVALID_USAGE = 64  # EX_USAGE

try:
    import yaml  # опционально: если есть PyYAML — используем; если нет, упадём на JSON
except Exception:
    yaml = None  # type: ignore


@dataclass
class TLSConfig:
    verify: t.Union[bool, str] = True          # True|False|/path/to/cabundle
    client: t.Optional[t.Tuple[str, str]] = None  # (cert, key)


@dataclass
class Ctx:
    base_url: str
    token: str
    tls: TLSConfig
    timeout: float
    retries: int
    output_pretty: bool


def _load_config_file(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        if path.endswith(".json") or yaml is None:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        # YAML доступен
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _token_from_source(val: str) -> str:
    """
    Источник токена:
    - пусто -> ""
    - "file:/path" -> чтение из файла
    - "-" -> запросить интерактивно (скрытый ввод)
    - иначе -> воспринимать как сырой токен
    """
    if not val:
        return ""
    if val == "-":
        return getpass.getpass("Access token: ").strip()
    if val.startswith("file:"):
        p = val.split(":", 1)[1]
        with open(p, "r", encoding="utf-8") as f:
            return f.read().strip()
    return val.strip()


def _build_tls(ca_cert: str, client_cert: str, client_key: str) -> TLSConfig:
    verify: t.Union[bool, str] = True
    if ca_cert:
        verify = ca_cert
    client = None
    if client_cert and client_key:
        client = (client_cert, client_key)
    return TLSConfig(verify=verify, client=client)


def _ctx_from_args(args: argparse.Namespace) -> Ctx:
    # Конфиг из файла
    file_cfg = _load_config_file(args.config or DEFAULT_CONFIG)
    base_url = (
        args.base_url
        or file_cfg.get("base_url")
        or DEFAULT_BASE_URL
    )
    token = _token_from_source(
        args.token
        or file_cfg.get("token", "")
        or DEFAULT_TOKEN
    )
    # CA / mTLS
    ca_cert = args.ca_cert or file_cfg.get("ca_cert") or DEFAULT_CA_CERT
    client_cert = args.client_cert or file_cfg.get("client_cert") or DEFAULT_CLIENT_CERT
    client_key = args.client_key or file_cfg.get("client_key") or DEFAULT_CLIENT_KEY

    tls = _build_tls(ca_cert, client_cert, client_key)

    timeout = float(args.timeout or file_cfg.get("timeout_s") or DEFAULT_TIMEOUT)
    retries = int(args.retries or file_cfg.get("retries") or DEFAULT_RETRIES)
    pretty = bool(args.pretty or file_cfg.get("pretty", True))
    return Ctx(base_url=base_url, token=token, tls=tls, timeout=timeout, retries=retries, output_pretty=pretty)


def _http(
    ctx: Ctx,
    method: str,
    path: str,
    *,
    json_body: t.Optional[dict] = None,
    params: t.Optional[dict] = None,
) -> requests.Response:
    url = ctx.base_url.rstrip("/") + path
    headers = {
        "User-Agent": "avmctl/1.0",
        "Accept": "application/json",
    }
    if ctx.token:
        headers["Authorization"] = f"Bearer {ctx.token}"

    last_exc: t.Optional[BaseException] = None
    for attempt in range(1, ctx.retries + 1):
        try:
            resp = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                json=json_body,
                params=params,
                timeout=ctx.timeout,
                verify=ctx.tls.verify,
                cert=ctx.tls.client,
            )
            return resp
        except requests.exceptions.RequestException as e:
            last_exc = e
            if attempt >= ctx.retries:
                raise
            # экспоненциальная задержка с джиттером
            sleep_s = min(0.2 * (2 ** (attempt - 1)), 2.0) + (0.05 * (attempt - 1))
            time.sleep(sleep_s)
    # не должны сюда дойти
    raise last_exc or RuntimeError("unknown network error")


def _print_json(data: t.Any, pretty: bool) -> None:
    if pretty:
        print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False))
    else:
        print(json.dumps(data, ensure_ascii=False, separators=(",", ":")))


def _exit_by_status(resp: requests.Response) -> int:
    code = resp.status_code
    if code // 100 == 2:
        return EXIT_OK
    if code == 400:
        return EXIT_BAD_REQUEST
    if code in (401, 403):
        return EXIT_FORBIDDEN
    if code == 404:
        return EXIT_NOT_FOUND
    if code // 100 == 5:
        return EXIT_SERVER_ERROR
    return EXIT_BAD_REQUEST


# ---------- Commands implementations ----------

def cmd_net_up(ctx: Ctx, profile: t.Optional[str]) -> int:
    payload = {"profile": profile} if profile else {}
    try:
        r = _http(ctx, "POST", "/v1/net/up", json_body=payload)
    except requests.exceptions.RequestException as e:
        _print_json({"error": f"net up failed: {e}"}, ctx.output_pretty)
        return EXIT_NET_ERROR
    exitc = _exit_by_status(r)
    try:
        data = r.json()
    except Exception:
        data = {"status": "error", "http_status": r.status_code, "text": r.text}
    _print_json(data, ctx.output_pretty)
    return exitc


def cmd_net_down(ctx: Ctx) -> int:
    try:
        r = _http(ctx, "POST", "/v1/net/down")
    except requests.exceptions.RequestException as e:
        _print_json({"error": f"net down failed: {e}"}, ctx.output_pretty)
        return EXIT_NET_ERROR
    exitc = _exit_by_status(r)
    try:
        data = r.json()
    except Exception:
        data = {"status": "error", "http_status": r.status_code, "text": r.text}
    _print_json(data, ctx.output_pretty)
    return exitc


def cmd_net_status(ctx: Ctx) -> int:
    try:
        r = _http(ctx, "GET", "/v1/net/status")
    except requests.exceptions.RequestException as e:
        _print_json({"active": False, "error": f"net status failed: {e}"}, ctx.output_pretty)
        return EXIT_NET_ERROR
    exitc = _exit_by_status(r)
    try:
        data = r.json()
    except Exception:
        data = {"status": "error", "http_status": r.status_code, "text": r.text}
    _print_json(data, ctx.output_pretty)
    return exitc


def cmd_vm_create(ctx: Ctx, name: str, image: str, cpu: int, mem_mb: int, disk_gb: int, net_profile: t.Optional[str]) -> int:
    payload = {"name": name, "image": image, "cpu": cpu, "memory_mb": mem_mb, "disk_gb": disk_gb}
    if net_profile:
        payload["network_profile"] = net_profile
    try:
        r = _http(ctx, "POST", "/v1/vm", json_body=payload)
    except requests.exceptions.RequestException as e:
        _print_json({"error": f"vm create failed: {e}"}, ctx.output_pretty)
        return EXIT_NET_ERROR
    exitc = _exit_by_status(r)
    try:
        data = r.json()
    except Exception:
        data = {"status": "error", "http_status": r.status_code, "text": r.text}
    _print_json(data, ctx.output_pretty)
    return exitc


def cmd_vm_start(ctx: Ctx, vm_id: str) -> int:
    try:
        r = _http(ctx, "POST", f"/v1/vm/{vm_id}/start")
    except requests.exceptions.RequestException as e:
        _print_json({"error": f"vm start failed: {e}"}, ctx.output_pretty)
        return EXIT_NET_ERROR
    exitc = _exit_by_status(r)
    try:
        data = r.json()
    except Exception:
        data = {"status": "error", "http_status": r.status_code, "text": r.text}
    _print_json(data, ctx.output_pretty)
    return exitc


def cmd_vm_stop(ctx: Ctx, vm_id: str) -> int:
    try:
        r = _http(ctx, "POST", f"/v1/vm/{vm_id}/stop")
    except requests.exceptions.RequestException as e:
        _print_json({"error": f"vm stop failed: {e}"}, ctx.output_pretty)
        return EXIT_NET_ERROR
    exitc = _exit_by_status(r)
    try:
        data = r.json()
    except Exception:
        data = {"status": "error", "http_status": r.status_code, "text": r.text}
    _print_json(data, ctx.output_pretty)
    return exitc


def cmd_vm_snapshot(ctx: Ctx, vm_id: str, snap_name: str) -> int:
    payload = {"name": snap_name}
    try:
        r = _http(ctx, "POST", f"/v1/vm/{vm_id}/snapshot", json_body=payload)
    except requests.exceptions.RequestException as e:
        _print_json({"error": f"vm snapshot failed: {e}"}, ctx.output_pretty)
        return EXIT_NET_ERROR
    exitc = _exit_by_status(r)
    try:
        data = r.json()
    except Exception:
        data = {"status": "error", "http_status": r.status_code, "text": r.text}
    _print_json(data, ctx.output_pretty)
    return exitc


def cmd_vm_backup(ctx: Ctx, vm_id: str, dest: str) -> int:
    payload = {"destination": dest}
    try:
        r = _http(ctx, "POST", f"/v1/vm/{vm_id}/backup", json_body=payload)
    except requests.exceptions.RequestException as e:
        _print_json({"error": f"vm backup failed: {e}"}, ctx.output_pretty)
        return EXIT_NET_ERROR
    exitc = _exit_by_status(r)
    try:
        data = r.json()
    except Exception:
        data = {"status": "error", "http_status": r.status_code, "text": r.text}
    _print_json(data, ctx.output_pretty)
    return exitc


def cmd_vm_delete(ctx: Ctx, vm_id: str) -> int:
    try:
        r = _http(ctx, "DELETE", f"/v1/vm/{vm_id}")
    except requests.exceptions.RequestException as e:
        _print_json({"error": f"vm delete failed: {e}"}, ctx.output_pretty)
        return EXIT_NET_ERROR
    exitc = _exit_by_status(r)
    try:
        data = r.json()
    except Exception:
        data = {"status": "error", "http_status": r.status_code, "text": r.text}
    _print_json(data, ctx.output_pretty)
    return exitc


def cmd_health(ctx: Ctx, probe: str) -> int:
    path = "/v1/health"
    if probe == "liveness":
        path = "/v1/health/liveness"
    elif probe == "readiness":
        path = "/v1/health/readiness"
    elif probe == "startup":
        path = "/v1/health/startup"
    try:
        r = _http(ctx, "GET", path)
    except requests.exceptions.RequestException as e:
        _print_json({"status": "fail", "error": f"health {probe} failed: {e}"}, ctx.output_pretty)
        return EXIT_NET_ERROR
    exitc = _exit_by_status(r)
    try:
        data = r.json()
    except Exception:
        data = {"status": "error", "http_status": r.status_code, "text": r.text}
    _print_json(data, ctx.output_pretty)
    return exitc


# ---------- Argparse / entry point ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="avmctl",
        description="Aethernova AVM control CLI (VM, network, health).",
    )
    p.add_argument("--config", help=f"Путь к конфигу CLI (YAML/JSON). По умолчанию: {DEFAULT_CONFIG}")
    p.add_argument("--base-url", help=f"Базовый URL API (default: {DEFAULT_BASE_URL})")
    p.add_argument("--token", help="Bearer токен: raw | file:/path | '-' (ввод)")
    p.add_argument("--ca-cert", help="Путь к CA bundle для TLS проверки")
    p.add_argument("--client-cert", help="Путь к клиентскому сертификату (PEM) для mTLS")
    p.add_argument("--client-key", help="Путь к приватному ключу (PEM) для mTLS")
    p.add_argument("--timeout", type=float, help=f"Таймаут запроса, сек (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--retries", type=int, help=f"Кол-во попыток на сетевые ошибки (default: {DEFAULT_RETRIES})")
    p.add_argument("--no-pretty", dest="pretty", action="store_false", help="Компактный JSON вывод")
    p.set_defaults(pretty=True)

    sub = p.add_subparsers(dest="cmd", required=True)

    # net
    net = sub.add_parser("net", help="Операции сети (VPN/mesh)")
    net_sub = net.add_subparsers(dest="subcmd", required=True)
    net_up = net_sub.add_parser("up", help="Включить сетевой профиль")
    net_up.add_argument("--profile", help="Имя профиля из configs/network/profiles.yaml")
    net_sub.add_parser("down", help="Выключить активный профиль")
    net_sub.add_parser("status", help="Статус сети")

    # vm
    vm = sub.add_parser("vm", help="Операции с виртуальными машинами")
    vm_sub = vm.add_subparsers(dest="subcmd", required=True)
    vm_create = vm_sub.add_parser("create", help="Создать спецификацию VM")
    vm_create.add_argument("--name", required=True)
    vm_create.add_argument("--image", required=True, help="Идентификатор/путь образа")
    vm_create.add_argument("--cpu", type=int, default=2)
    vm_create.add_argument("--mem", type=int, dest="mem_mb", default=4096, help="Память, МБ")
    vm_create.add_argument("--disk", type=int, dest="disk_gb", default=20, help="Диск, ГБ")
    vm_create.add_argument("--net-profile", help="Имя сетевого профиля для VM")
    vm_start = vm_sub.add_parser("start", help="Запустить VM")
    vm_start.add_argument("--id", required=True)
    vm_stop = vm_sub.add_parser("stop", help="Остановить VM")
    vm_stop.add_argument("--id", required=True)
    vm_snap = vm_sub.add_parser("snapshot", help="Создать снапшот VM")
    vm_snap.add_argument("--id", required=True)
    vm_snap.add_argument("--name", required=True)
    vm_bak = vm_sub.add_parser("backup", help="Сделать бэкап VM")
    vm_bak.add_argument("--id", required=True)
    vm_bak.add_argument("--dest", required=True, help="Назначение (например s3://bucket/key)")
    vm_del = vm_sub.add_parser("delete", help="Удалить VM")
    vm_del.add_argument("--id", required=True)

    # health
    health = sub.add_parser("health", help="Проверки состояния сервиса")
    health.add_argument("--probe", choices=["all", "liveness", "readiness", "startup"], default="all")

    return p


def main(argv: t.Optional[t.List[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[0:]
    parser = build_parser()
    args = parser.parse_args(argv[1:])
    ctx = _ctx_from_args(args)

    try:
        if args.cmd == "net":
            if args.subcmd == "up":
                return cmd_net_up(ctx, args.profile)
            if args.subcmd == "down":
                return cmd_net_down(ctx)
            if args.subcmd == "status":
                return cmd_net_status(ctx)
            parser.error("неизвестная подкоманда net")

        if args.cmd == "vm":
            if args.subcmd == "create":
                return cmd_vm_create(ctx, args.name, args.image, args.cpu, args.mem_mb, args.disk_gb, args.net_profile)
            if args.subcmd == "start":
                return cmd_vm_start(ctx, args.id)
            if args.subcmd == "stop":
                return cmd_vm_stop(ctx, args.id)
            if args.subcmd == "snapshot":
                return cmd_vm_snapshot(ctx, args.id, args.name)
            if args.subcmd == "backup":
                return cmd_vm_backup(ctx, args.id, args.dest)
            if args.subcmd == "delete":
                return cmd_vm_delete(ctx, args.id)
            parser.error("неизвестная подкоманда vm")

        if args.cmd == "health":
            return cmd_health(ctx, args.probe)

        parser.error("неизвестная команда")
    except KeyboardInterrupt:
        _print_json({"error": "interrupted"}, ctx.output_pretty)
        return EXIT_INVALID_USAGE


if __name__ == "__main__":
    sys.exit(main())
