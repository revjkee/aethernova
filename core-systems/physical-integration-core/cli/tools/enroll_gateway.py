# physical-integration-core/cli/tools/enroll_gateway.py
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

# Внутренние зависимости
from physical_integration.edge.enrollment import (
    Settings as EnrollSettings,
    EnrollmentClient,
    EnrollmentState,
    _parse_cert_dates,  # безопасно: используем для статуса
)

# Опциональные зависимости
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

LOG = logging.getLogger("cli.enroll_gateway")


# ---------------------------
# Конфигурация CLI
# ---------------------------
@dataclass
class CLIConfig:
    # Базовый URL контроллера (для тестов соединения и ensure)
    base_url: str = os.getenv("ENROLL_BASE_URL", "https://controller.local")
    # Вывод JSON
    json_out: bool = os.getenv("CLI_JSON", "true").lower() in {"1", "true", "yes"}
    # Формат логов: json|text
    log_format: str = os.getenv("LOG_FORMAT", "json").lower()
    # Уровень логирования
    log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()
    # Таймауты сети
    http_timeout: float = float(os.getenv("CLI_HTTP_TIMEOUT", "10.0"))
    # Путь к состоянию enrollment
    state_dir: Path = Path(os.getenv("ENROLL_DATA_DIR", "/var/lib/physical-integration/enroll")).resolve()
    # Проверяемый путь здоровья контроллера
    health_path: str = os.getenv("CLI_HEALTH_PATH", "/health")
    # Использовать сертификаты из state вместо SEC_MTLS_CERT/KEY
    use_state_cert: bool = os.getenv("CLI_USE_STATE_CERT", "true").lower() in {"1", "true", "yes"}


# ---------------------------
# Логирование и вывод
# ---------------------------
def setup_logging(cfg: CLIConfig) -> None:
    h = logging.StreamHandler()
    if cfg.log_format == "json":
        class _JSON(logging.Formatter):
            def format(self, r: logging.LogRecord) -> str:
                data = {
                    "level": r.levelname,
                    "logger": r.name,
                    "msg": r.getMessage(),
                }
                if r.exc_info:
                    data["exc_info"] = self.formatException(r.exc_info)
                return json.dumps(data, ensure_ascii=False)
        h.setFormatter(_JSON())
    else:
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(getattr(logging, cfg.log_level, logging.INFO))


def out(data: Any, *, json_out: bool) -> None:
    if json_out:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        if isinstance(data, (dict, list)):
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print(str(data))


# ---------------------------
# systemd-notify (без зависимостей)
# ---------------------------
def sd_notify(message: str) -> None:
    sock_path = os.environ.get("NOTIFY_SOCKET")
    if not sock_path:
        return
    addr = sock_path
    if sock_path.startswith("@"):  # абстрактный сокет
        addr = "\0" + sock_path[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.send(message.encode("utf-8"))
    except Exception:
        pass


# ---------------------------
# Утилиты состояния/сертификатов
# ---------------------------
def load_state(cfg: CLIConfig) -> Optional[EnrollmentState]:
    path = cfg.state_dir / "state.json"
    return EnrollmentState.load(path)  # type: ignore


def state_summary(st: EnrollmentState) -> Dict[str, Any]:
    nb = st.not_before
    na = st.not_after
    summary: Dict[str, Any] = {
        "device_id": st.device_id,
        "installed": st.installed,
        "key_path": st.key_path,
        "cert_path": st.cert_path,
        "chain_path": st.chain_path,
        "not_before": nb,
        "not_after": na,
        "last_enroll_at": st.last_enroll_at,
        "last_error": st.last_error,
    }
    return summary


# ---------------------------
# Команды
# ---------------------------
async def cmd_status(args: argparse.Namespace, cfg: CLIConfig) -> int:
    st = load_state(cfg)
    if not st:
        out({"installed": False, "error": "state not found"}, json_out=cfg.json_out)
        return 3
    # Верифицируем даты (если возможно)
    details = state_summary(st)
    if st.cert_path:
        try:
            with open(st.cert_path, "r", encoding="utf-8") as f:
                cert_pem = f.read()
            nb, na = _parse_cert_dates(cert_pem)
            if nb:
                details["not_before"] = nb.isoformat()
            if na:
                details["not_after"] = na.isoformat()
        except Exception:
            pass
    out(details, json_out=cfg.json_out)
    return 0


async def cmd_device_id(args: argparse.Namespace, cfg: CLIConfig) -> int:
    st = load_state(cfg)
    if not st:
        out({"error": "state not found"}, json_out=cfg.json_out)
        return 3
    out({"device_id": st.device_id}, json_out=cfg.json_out)
    return 0


async def cmd_enroll_once(args: argparse.Namespace, cfg: CLIConfig) -> int:
    client = EnrollmentClient(EnrollSettings())
    try:
        await client.ensure_enrolled()
        sd_notify("STATUS=Enrollment succeeded\n")
        out({"result": "enrolled", "device_id": client.state.device_id}, json_out=cfg.json_out)
        return 0
    except Exception as ex:
        sd_notify(f"STATUS=Enrollment failed: {ex}\n")
        out({"error": str(ex)}, json_out=cfg.json_out)
        return 2


async def cmd_run(args: argparse.Namespace, cfg: CLIConfig) -> int:
    # Долгоживущий процесс для systemd
    stop = asyncio.Event()

    def _stop(*_: Any) -> None:
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib_suppress():
            loop.add_signal_handler(sig, _stop)

    client = EnrollmentClient(EnrollSettings())
    sd_notify("STATUS=Starting enrollment loop\n")
    sd_notify("READY=1\n")
    async def _runner():
        await client.run_forever()

    task = asyncio.create_task(_runner())
    await stop.wait()
    task.cancel()
    with contextlib_suppress():
        await task
    sd_notify("STATUS=Stopped\n")
    return 0


async def cmd_ensure_twin(args: argparse.Namespace, cfg: CLIConfig) -> int:
    client = EnrollmentClient(EnrollSettings())
    try:
        # ensure_twin косвенно делается в ensure_enrolled(); здесь вызываем напрямую приватный метод
        if hasattr(client, "_ensure_twin"):
            await getattr(client, "_ensure_twin")()
        out({"result": "twin_ensured", "device_id": client.state.device_id}, json_out=cfg.json_out)
        return 0
    except Exception as ex:
        out({"error": str(ex)}, json_out=cfg.json_out)
        return 2


async def cmd_show_cert(args: argparse.Namespace, cfg: CLIConfig) -> int:
    st = load_state(cfg)
    if not st or not st.cert_path:
        out({"error": "certificate not installed"}, json_out=cfg.json_out)
        return 3
    pem = Path(st.cert_path).read_text(encoding="utf-8")
    if args.pem:
        print(pem, end="")
        return 0
    nb, na = _parse_cert_dates(pem)
    info = {
        "cert_path": st.cert_path,
        "not_before": nb.isoformat() if nb else None,
        "not_after": na.isoformat() if na else None,
    }
    out(info, json_out=cfg.json_out)
    return 0


async def cmd_test_mtls(args: argparse.Namespace, cfg: CLIConfig) -> int:
    if httpx is None:
        out({"error": "httpx not available"}, json_out=cfg.json_out)
        return 4

    st = load_state(cfg)
    cert: Optional[str] = None
    key: Optional[str] = None
    if cfg.use_state_cert and st and st.cert_path:
        cert = st.cert_path
        key = st.key_path
    else:
        cert = os.getenv("SEC_MTLS_CERT")
        key = os.getenv("SEC_MTLS_KEY")

    if not (cert and key):
        out({"error": "mTLS cert/key not configured"}, json_out=cfg.json_out)
        return 3

    url = cfg.base_url.rstrip("/") + args.path
    try:
        async with httpx.AsyncClient(timeout=cfg.http_timeout, verify=True, cert=(cert, key)) as cli:
            r = await cli.get(url)
            ok = r.status_code in (200, 204)
            out({"url": url, "status": r.status_code, "ok": ok, "body": (r.text[:2000] if r.text else "")}, json_out=cfg.json_out)
            return 0 if ok else 2
    except Exception as ex:
        out({"url": url, "error": str(ex)}, json_out=cfg.json_out)
        return 2


# ---------------------------
# Парсер аргументов
# ---------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="enroll-gateway", description="Gateway enrollment utilities")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_status = sub.add_parser("status", help="Show enrollment status")
    s_status.set_defaults(fn=cmd_status)

    s_id = sub.add_parser("device-id", help="Print device ID derived during enrollment")
    s_id.set_defaults(fn=cmd_device_id)

    s_once = sub.add_parser("enroll-once", help="Enroll or renew once and exit")
    s_once.set_defaults(fn=cmd_enroll_once)

    s_run = sub.add_parser("run", help="Run continuous enrollment/renewal loop (systemd-friendly)")
    s_run.set_defaults(fn=cmd_run)

    s_twin = sub.add_parser("ensure-twin", help="Ensure twin record exists on controller (idempotent)")
    s_twin.set_defaults(fn=cmd_ensure_twin)

    s_cert = sub.add_parser("show-cert", help="Show installed certificate info or PEM")
    s_cert.add_argument("--pem", action="store_true", help="Print full PEM instead of JSON")
    s_cert.set_defaults(fn=cmd_show_cert)

    s_test = sub.add_parser("test-mtls", help="Test mTLS connection to controller")
    s_test.add_argument("--path", default="/health", help="Path to request (default: /health)")
    s_test.set_defaults(fn=cmd_test_mtls)

    return p


# ---------------------------
# Вспомогательное suppress
# ---------------------------
class contextlib_suppress:
    def __init__(self, *exc: Any) -> None:
        self.exc = exc or (Exception,)
    def __enter__(self) -> None:
        return None
    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc is not None and issubclass(exc_type, self.exc)


# ---------------------------
# main
# ---------------------------
def main(argv: Optional[list[str]] = None) -> int:
    cfg = CLIConfig()
    setup_logging(cfg)
    parser = build_parser()
    ns = parser.parse_args(argv or sys.argv[1:])
    try:
        return asyncio.run(ns.fn(ns, cfg))  # type: ignore[attr-defined]
    except KeyboardInterrupt:
        return 130
    except Exception as ex:
        LOG.error("fatal: %s", ex)
        if cfg.json_out:
            out({"error": str(ex)}, json_out=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
