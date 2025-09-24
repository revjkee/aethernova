# chronowatch-core/cli/admin.py
# ChronoWatch Core — административный CLI.
# Python 3.11+. Без обязательных внешних зависимостей. Опционально: grpcio, PyYAML, PyJWT.

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

# -----------------------------
# Опциональные зависимости
# -----------------------------
HAS_YAML = False
try:
    import yaml  # type: ignore
    HAS_YAML = True
except Exception:
    pass

HAS_GRPC = False
try:
    import grpc  # type: ignore
    from grpc_health.v1 import health_pb2, health_pb2_grpc  # type: ignore
    HAS_GRPC = True
except Exception:
    pass

# -----------------------------
# Общие константы и коды выхода
# -----------------------------
EXIT_OK = 0
EXIT_GENERIC = 1
EXIT_INVALID_ARGS = 64
EXIT_NOT_FOUND = 66
EXIT_UNAVAILABLE = 69
EXIT_CONFIG_INVALID = 78
EXIT_FROZEN = 2

APP_NAME = "chronowatch-core"


# -----------------------------
# Утилиты вывода
# -----------------------------
def _print(data: Any, json_flag: bool) -> None:
    if json_flag:
        print(json.dumps(data, ensure_ascii=False, indent=None))
    else:
        if isinstance(data, (dict, list)):
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print(str(data))


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _load_yaml_or_json(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        if not HAS_YAML:
            raise RuntimeError("Требуется PyYAML для чтения YAML")
        return yaml.safe_load(text) or {}
    return json.loads(text)


# -----------------------------
# version
# -----------------------------
def cmd_version(args: argparse.Namespace) -> int:
    data = {
        "service": APP_NAME,
        "version": os.getenv("APP_VERSION", "-"),
        "git_sha": os.getenv("GIT_SHA", "-"),
        "build_date": os.getenv("BUILD_DATE", "-"),
        "python": sys.version.split()[0],
    }
    _print(data if args.json else f"{APP_NAME} {data['version']} ({data['git_sha']})", args.json)
    return EXIT_OK


# -----------------------------
# gRPC health
# -----------------------------
def _grpc_channel(address: str, timeout: float, tls: bool, ca: Optional[str], cert: Optional[str], key: Optional[str]):
    if not HAS_GRPC:
        raise RuntimeError("grpcio не установлен")
    if tls:
        ssl_creds = None
        if cert and key:
            with open(cert, "rb") as cf, open(key, "rb") as kf:
                cert_chain = cf.read()
                private_key = kf.read()
            root = None
            if ca:
                with open(ca, "rb") as caf:
                    root = caf.read()
            ssl_creds = grpc.ssl_channel_credentials(root_certificates=root, private_key=private_key, certificate_chain=cert_chain)
        else:
            root = None
            if ca:
                with open(ca, "rb") as caf:
                    root = caf.read()
            ssl_creds = grpc.ssl_channel_credentials(root_certificates=root)
        options = [
            ("grpc.max_receive_message_length", 50 * 1024 * 1024),
            ("grpc.keepalive_time_ms", 60000),
        ]
        return grpc.secure_channel(address, ssl_creds, options=options)
    else:
        return grpc.insecure_channel(address)


def cmd_grpc_health(args: argparse.Namespace) -> int:
    if not HAS_GRPC:
        _err("grpcio не установлен")
        return EXIT_UNAVAILABLE
    address = args.address
    try:
        ch = _grpc_channel(address, args.timeout, args.tls, args.ca, args.cert, args.key)
        stub = health_pb2_grpc.HealthStub(ch)
        req = health_pb2.HealthCheckRequest(service=args.service or "")
        resp = stub.Check(req, timeout=args.timeout)
        serving = resp.status == health_pb2.HealthCheckResponse.SERVING
        data = {
            "address": address,
            "service": args.service or "",
            "status": "SERVING" if serving else "NOT_SERVING",
        }
        _print(data, args.json)
        return EXIT_OK if serving else EXIT_UNAVAILABLE
    except Exception as e:
        _err(f"gRPC health check 실패: {e}")
        return EXIT_UNAVAILABLE


# -----------------------------
# maintenance (freeze)
# -----------------------------
def cmd_maintenance_check(args: argparse.Namespace) -> int:
    try:
        from chronowatch.windows.freeze import FreezeManager  # type: ignore
    except Exception:
        _err("Не найден модуль chronowatch.windows.freeze")
        return EXIT_NOT_FOUND

    file_path = args.file or os.getenv("CHRONOWATCH_MAINTENANCE_FILE", "")
    if not file_path:
        _err("Укажите --file или CHRONOWATCH_MAINTENANCE_FILE")
        return EXIT_INVALID_ARGS

    scope = {}
    for item in args.scope:
        if "=" not in item:
            _err(f"Некорректный элемент scope: {item}, ожидается key=value")
            return EXIT_INVALID_ARGS
        k, v = item.split("=", 1)
        scope[k.strip()] = v.strip()

    mgr = FreezeManager(Path(file_path))
    decision = mgr.is_frozen(candidate_scope=scope, emergency_change=args.emergency)
    out = {
        "frozen": decision.frozen,
        "reason": decision.reason,
        "window_name": decision.window_name,
        "blackout": decision.blackout,
        "severity": decision.severity,
        "interval_utc": [
            decision.interval_utc[0].isoformat() if decision.interval_utc else None,
            decision.interval_utc[1].isoformat() if decision.interval_utc else None,
        ] if decision.interval_utc else None,
        "scope": decision.scope_matched,
    }
    _print(out, args.json)
    return EXIT_FROZEN if decision.frozen else EXIT_OK


def cmd_maintenance_next(args: argparse.Namespace) -> int:
    try:
        from chronowatch.windows.freeze import FreezeManager  # type: ignore
    except Exception:
        _err("Не найден модуль chronowatch.windows.freeze")
        return EXIT_NOT_FOUND

    file_path = args.file or os.getenv("CHRONOWATCH_MAINTENANCE_FILE", "")
    if not file_path:
        _err("Укажите --file или CHRONOWATCH_MAINTENANCE_FILE")
        return EXIT_INVALID_ARGS

    scope = {}
    for item in args.scope:
        if "=" not in item:
            _err(f"Некорректный элемент scope: {item}, ожидается key=value")
            return EXIT_INVALID_ARGS
        k, v = item.split("=", 1)
        scope[k.strip()] = v.strip()

    mgr = FreezeManager(Path(file_path))
    nxt = mgr.next_window(candidate_scope=scope)
    if not nxt:
        _print({"next": None}, args.json)
        return EXIT_OK
    name, s, e, blackout = nxt
    _print({"next": {"name": name, "start_utc": s.isoformat(), "end_utc": e.isoformat(), "blackout": blackout}}, args.json)
    return EXIT_OK


# -----------------------------
# config validation
# -----------------------------
def _validate_logging_structure(cfg: Dict[str, Any]) -> Dict[str, Any]:
    issues: list[str] = []

    # version
    if cfg.get("version") != 1:
        issues.append("logging.yaml: поле 'version' должно быть равно 1")

    # formatters/handlers/root обязательны
    for key in ("formatters", "handlers", "root"):
        if key not in cfg:
            issues.append(f"logging.yaml: отсутствует раздел '{key}'")

    # handlers указывают на существующие formatters
    fmts = set((cfg.get("formatters") or {}).keys())
    for name, h in (cfg.get("handlers") or {}).items():
        fmt = (h or {}).get("formatter")
        if fmt and fmt not in fmts:
            issues.append(f"handler '{name}': formatter '{fmt}' не найден")

    # loggers не должны дублировать handlers root-а без propagate=false
    for lname, l in (cfg.get("loggers") or {}).items():
        if l and l.get("handlers") and l.get("propagate", False):
            issues.append(f"logger '{lname}': есть handlers и propagate=true (возможны дубли)")

    return {"valid": len(issues) == 0, "issues": issues}


def cmd_config_validate_logging(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        _err(f"Не найден файл: {path}")
        return EXIT_NOT_FOUND
    try:
        data = _load_yaml_or_json(path)
        res = _validate_logging_structure(data)
        _print(res, args.json)
        return EXIT_OK if res["valid"] else EXIT_CONFIG_INVALID
    except Exception as e:
        _err(f"Ошибка валидации: {e}")
        return EXIT_CONFIG_INVALID


def cmd_config_validate_maintenance(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        _err(f"Не найден файл: {path}")
        return EXIT_NOT_FOUND
    try:
        # Используем FreezeManager для проверки разбора и базовых инвариантов
        from chronowatch.windows.freeze import FreezeManager  # type: ignore
        mgr = FreezeManager(path)
        # Пробный вызов, чтобы прогнать парсинг и построение окон
        _ = mgr.config
        # Рендер следующего окна как smoke-test
        _ = mgr.next_window()
        _print({"valid": True}, args.json)
        return EXIT_OK
    except Exception as e:
        _print({"valid": False, "error": str(e)}, args.json)
        return EXIT_CONFIG_INVALID


# -----------------------------
# db (alembic)
# -----------------------------
def _run_shell(cmd: str, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> int:
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env or os.environ.copy(),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        _err("Команда превысила тайм-аут")
        return EXIT_UNAVAILABLE
    if out:
        print(out, end="")
    if err:
        _err(err)
    return proc.returncode


def cmd_db_migrate(args: argparse.Namespace) -> int:
    alembic_ini = args.alembic_ini or os.getenv("ALEMBIC_INI") or "alembic.ini"
    cmd = f"alembic -c {shlex.quote(alembic_ini)} upgrade head"
    rc = _run_shell(cmd, timeout=args.timeout)
    return EXIT_OK if rc == 0 else EXIT_GENERIC


def cmd_db_downgrade(args: argparse.Namespace) -> int:
    alembic_ini = args.alembic_ini or os.getenv("ALEMBIC_INI") or "alembic.ini"
    rev = args.revision
    cmd = f"alembic -c {shlex.quote(alembic_ini)} downgrade {shlex.quote(rev)}"
    rc = _run_shell(cmd, timeout=args.timeout)
    return EXIT_OK if rc == 0 else EXIT_GENERIC


# -----------------------------
# Парсер аргументов
# -----------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="chronowatch-admin",
        description="Административный CLI ChronoWatch Core",
    )
    p.add_argument("--json", action="store_true", help="Вывод в JSON")
    sub = p.add_subparsers(dest="cmd", required=True)

    # version
    sp = sub.add_parser("version", help="Показать версию")
    sp.set_defaults(func=cmd_version)

    # grpc
    grp = sub.add_parser("grpc", help="gRPC операции")
    grpc_sub = grp.add_subparsers(dest="grpc_cmd", required=True)

    ghealth = grpc_sub.add_parser("health", help="Health-check gRPC сервиса")
    ghealth.add_argument("--address", required=True, help="host:port")
    ghealth.add_argument("--service", default="", help="Имя сервиса (Health service.name)")
    ghealth.add_argument("--timeout", type=float, default=3.0)
    ghealth.add_argument("--tls", action="store_true")
    ghealth.add_argument("--ca", help="CA файл (опционально)")
    ghealth.add_argument("--cert", help="Клиентский сертификат (mTLS)")
    ghealth.add_argument("--key", help="Клиентский ключ (mTLS)")
    ghealth.set_defaults(func=cmd_grpc_health)

    # maintenance
    m = sub.add_parser("maintenance", help="Операции техокон")
    msub = m.add_subparsers(dest="mw_cmd", required=True)

    mcheck = msub.add_parser("check", help="Проверить, действует ли фриз")
    mcheck.add_argument("--file", help="Путь к maintenance_window.yaml")
    mcheck.add_argument("--scope", "-s", action="append", default=[], help="key=value, например env=prod service=api")
    mcheck.add_argument("--emergency", action="store_true", help="Разрешать по emergency-исключению")
    mcheck.set_defaults(func=cmd_maintenance_check)

    mnext = msub.add_parser("next", help="Следующее окно")
    mnext.add_argument("--file", help="Путь к maintenance_window.yaml")
    mnext.add_argument("--scope", "-s", action="append", default=[], help="key=value фильтры")
    mnext.set_defaults(func=cmd_maintenance_next)

    # config
    c = sub.add_parser("config", help="Валидация конфигов")
    csub = c.add_subparsers(dest="cfg_cmd", required=True)

    clog = csub.add_parser("validate-logging", help="Проверить logging.yaml")
    clog.add_argument("--file", required=True, help="Путь к logging.yaml или .json")
    clog.set_defaults(func=cmd_config_validate_logging)

    cmw = csub.add_parser("validate-maintenance", help="Проверить maintenance_window.yaml")
    cmw.add_argument("--file", required=True, help="Путь к maintenance_window.yaml")
    cmw.set_defaults(func=cmd_config_validate_maintenance)

    # db
    d = sub.add_parser("db", help="Операции БД (alembic)")
    dsub = d.add_subparsers(dest="db_cmd", required=True)

    dmig = dsub.add_parser("migrate", help="alembic upgrade head")
    dmig.add_argument("--alembic-ini", help="Путь к alembic.ini (дефолт ALEMBIC_INI/alembic.ini)")
    dmig.add_argument("--timeout", type=int, default=600)
    dmig.set_defaults(func=cmd_db_migrate)

    ddow = dsub.add_parser("downgrade", help="alembic downgrade <rev>")
    ddow.add_argument("revision", help="Ревизия, например -1 или base")
    ddow.add_argument("--alembic-ini", help="Путь к alembic.ini")
    ddow.add_argument("--timeout", type=int, default=600)
    ddow.set_defaults(func=cmd_db_downgrade)

    return p


# -----------------------------
# main
# -----------------------------
def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        _err("Прервано пользователем")
        return EXIT_GENERIC
    except AttributeError:
        parser.print_help()
        return EXIT_INVALID_ARGS
    except Exception as e:
        _err(f"Ошибка: {e}")
        return EXIT_GENERIC


if __name__ == "__main__":
    raise SystemExit(main())
