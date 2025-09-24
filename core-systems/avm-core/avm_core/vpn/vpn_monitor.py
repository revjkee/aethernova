#!/usr/bin/env python3
"""
avm_core.vpn.vpn_monitor — асинхронный монитор VPN с метриками Prometheus.

Возможности:
- Адаптеры: WireGuard, OpenVPN (systemd/status file), IPsec/strongSwan, Generic TCP.
- Критерии здоровья: наличие интерфейса/соединения, давность последнего handshake,
  успешное TCP‑соединение через туннель.
- Прометей‑метрики без сторонних библиотек: /metrics (text/plain; version=0.0.4).
- Конфигурация: YAML или JSON (автоопределение). Без PyYAML модуль fallback в JSON.
- Безопасность: фиксированные системные команды, таймауты, ограничение окружения.
- CLI: --config, --interval, --once, --metrics-port, --log-json, --log-level.

Пример конфигурации (YAML):
---
interval_seconds: 15
handshake_max_age_seconds: 180
connect_timeout_seconds: 3
metrics:
  enabled: true
  host: "0.0.0.0"
  port: 9103
tunnels:
  - name: "wg0"
    type: "wireguard"
    interface: "wg0"
    # необязательно, но полезно: TCP‑проверка доступности хоста через туннель
    tcp_probe:
      host: "10.6.0.1"
      port: 53
      # при необходимости привязка исходного адреса туннеля (Linux)
      bind_source_ip: "10.6.0.2"
  - name: "ovpn-client01"
    type: "openvpn"
    systemd_service: "openvpn-client@client01"
    # альтернативно: status_file: "/run/openvpn/client01.status"
    tcp_probe:
      host: "10.8.0.1"
      port: 443
  - name: "ipsec-site-a"
    type: "ipsec"
    connection: "site-a"
    tcp_probe:
      host: "172.16.1.10"
      port: 22
  - name: "generic-edge"
    type: "generic"
    tcp_probe:
      host: "100.64.0.10"
      port: 8443
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import datetime as dt
import functools
import ipaddress
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

# ========= ЛОГИРОВАНИЕ =========


def setup_logging(level: str = "INFO", json_mode: bool = False) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger()
    logger.handlers.clear()
    logger.setLevel(lvl)

    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            payload = {
                "ts": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "lvl": record.levelname,
                "logger": record.name,
                "msg": record.getMessage(),
            }
            if record.exc_info:
                payload["exc"] = self.formatException(record.exc_info)
            return json.dumps(payload, ensure_ascii=False)

    if json_mode:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    else:
        fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(fmt=fmt, datefmt="%Y-%m-%dT%H:%M:%SZ"))
        logger.addHandler(handler)


log = logging.getLogger("vpn.monitor")


# ========= УТИЛИТЫ =========


class ExecError(Exception):
    pass


async def run_cmd(
    argv: List[str],
    timeout: float = 3.0,
    check: bool = False,
    env: Optional[Mapping[str, str]] = None,
) -> Tuple[int, str, str]:
    """
    Безопасный запуск внешней команды с таймаутом.
    Возвращает (returncode, stdout, stderr).
    """
    # Ограниченное окружение
    safe_env = {"PATH": os.getenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")}
    if env:
        safe_env.update({k: str(v) for k, v in env.items()})

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=safe_env,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            raise ExecError(f"Timeout running: {' '.join(argv)}")
    except FileNotFoundError as e:
        raise ExecError(f"Command not found: {argv[0]}") from e

    rc = proc.returncode
    out = stdout_b.decode(errors="replace")
    err = stderr_b.decode(errors="replace")
    if check and rc != 0:
        raise ExecError(f"Command failed rc={rc}: {' '.join(argv)} | {err.strip()}")
    return rc, out, err


def now_ts() -> float:
    return time.time()


# ========= МЕТРИКИ PROMETHEUS =========


class MetricsRegistry:
    """
    Простейший потокобезопасный регистр метрик во внутреннем формате.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._gauges: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
        self._counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
        self._summaries: Dict[
            Tuple[str, Tuple[Tuple[str, str], ...]],
            Tuple[float, float, int],
        ] = {}  # sum, sumsq, count

    @staticmethod
    def _key(name: str, labels: Optional[Mapping[str, str]]) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
        items = tuple(sorted((labels or {}).items()))
        return name, items

    def gauge_set(self, name: str, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
        with self._lock:
            self._gauges[self._key(name, labels)] = float(value)

    def counter_inc(self, name: str, inc: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        with self._lock:
            k = self._key(name, labels)
            self._counters[k] = self._counters.get(k, 0.0) + inc

    def summary_obs(self, name: str, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
        with self._lock:
            k = self._key(name, labels)
            s, ss, c = self._summaries.get(k, (0.0, 0.0, 0))
            self._summaries[k] = (s + value, ss + value * value, c + 1)

    def render(self) -> str:
        """
        Экспорт в текстовый формат Prometheus exposition.
        """
        lines: List[str] = []
        with self._lock:
            for (name, labels), value in sorted(self._gauges.items()):
                label_s = ",".join(f'{k}="{v}"' for k, v in labels)
                lines.append(f'{name}{{{label_s}}} {value}')
            for (name, labels), value in sorted(self._counters.items()):
                label_s = ",".join(f'{k}="{v}"' for k, v in labels)
                lines.append(f'{name}_total{{{label_s}}} {value}')
            for (name, labels), (s, ss, c) in sorted(self._summaries.items()):
                label_s = ",".join(f'{k}="{v}"' for k, v in labels)
                # экспортируем простые агрегаты
                lines.append(f'{name}_count{{{label_s}}} {c}')
                lines.append(f'{name}_sum{{{label_s}}} {s}')
        return "\n".join(lines) + "\n"


class MetricsHandler(BaseHTTPRequestHandler):
    registry: MetricsRegistry = MetricsRegistry()

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found\n")
            return
        payload = self.registry.render().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args: Any) -> None:  # mute access logs
        return


def start_metrics_http(host: str, port: int, registry: MetricsRegistry) -> threading.Thread:
    MetricsHandler.registry = registry
    httpd = HTTPServer((host, port), MetricsHandler)
    t = threading.Thread(target=httpd.serve_forever, name="metrics-http", daemon=True)
    t.start()
    log.info("metrics server started on %s:%d", host, port)
    return t


# ========= КОНФИГУРАЦИЯ =========


@dataclasses.dataclass
class TCPProbe:
    host: str
    port: int
    connect_timeout_seconds: float = 3.0
    bind_source_ip: Optional[str] = None  # Linux SO_BINDTODEVICE недоступен без root; используем bind IP

    @staticmethod
    def from_dict(d: Mapping[str, Any], default_timeout: float) -> "TCPProbe":
        return TCPProbe(
            host=str(d["host"]),
            port=int(d["port"]),
            connect_timeout_seconds=float(d.get("connect_timeout_seconds", default_timeout)),
            bind_source_ip=str(d.get("bind_source_ip")) if d.get("bind_source_ip") else None,
        )


@dataclasses.dataclass
class Tunnel:
    name: str
    type: str  # wireguard | openvpn | ipsec | generic
    interface: Optional[str] = None  # wireguard
    systemd_service: Optional[str] = None  # openvpn
    status_file: Optional[str] = None  # openvpn
    connection: Optional[str] = None  # ipsec
    tcp_probe: Optional[TCPProbe] = None


@dataclasses.dataclass
class Config:
    interval_seconds: float = 15.0
    handshake_max_age_seconds: float = 180.0
    connect_timeout_seconds: float = 3.0
    metrics_enabled: bool = True
    metrics_host: str = "0.0.0.0"
    metrics_port: int = 9103
    tunnels: List[Tunnel] = dataclasses.field(default_factory=list)


def _try_load_yaml(path: str) -> Optional[Mapping[str, Any]]:
    try:
        import yaml  # type: ignore

        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)  # type: ignore
    except ModuleNotFoundError:
        return None


def load_config(path: Optional[str]) -> Config:
    if path:
        if path.endswith(".yaml") or path.endswith(".yml"):
            data = _try_load_yaml(path)
            if data is None:
                raise RuntimeError("PyYAML не установлен. Установите pyyaml или используйте JSON конфигурацию.")
        else:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
    else:
        # Минимум из переменных окружения
        data = {
            "interval_seconds": float(os.getenv("VPN_MON_INTERVAL", "15")),
            "handshake_max_age_seconds": float(os.getenv("VPN_MON_MAX_HANDSHAKE_AGE", "180")),
            "connect_timeout_seconds": float(os.getenv("VPN_MON_CONNECT_TIMEOUT", "3")),
            "metrics": {
                "enabled": os.getenv("VPN_MON_METRICS_ENABLED", "1") != "0",
                "host": os.getenv("VPN_MON_METRICS_HOST", "0.0.0.0"),
                "port": int(os.getenv("VPN_MON_METRICS_PORT", "9103")),
            },
            "tunnels": [],
        }

    metrics = data.get("metrics", {})
    cfg = Config(
        interval_seconds=float(data.get("interval_seconds", 15)),
        handshake_max_age_seconds=float(data.get("handshake_max_age_seconds", 180)),
        connect_timeout_seconds=float(data.get("connect_timeout_seconds", 3)),
        metrics_enabled=bool(metrics.get("enabled", True)),
        metrics_host=str(metrics.get("host", "0.0.0.0")),
        metrics_port=int(metrics.get("port", 9103)),
        tunnels=[],
    )
    for item in data.get("tunnels", []):
        tcp_probe = None
        if "tcp_probe" in item and item["tcp_probe"]:
            tcp_probe = TCPProbe.from_dict(item["tcp_probe"], cfg.connect_timeout_seconds)
        cfg.tunnels.append(
            Tunnel(
                name=str(item["name"]),
                type=str(item["type"]).lower(),
                interface=item.get("interface"),
                systemd_service=item.get("systemd_service"),
                status_file=item.get("status_file"),
                connection=item.get("connection"),
                tcp_probe=tcp_probe,
            )
        )
    return cfg


# ========= ПРОВЕРКИ =========


@dataclasses.dataclass
class CheckResult:
    name: str
    ok: bool
    reason: str
    details: Mapping[str, Any]
    duration_seconds: float


async def tcp_connect_check(probe: TCPProbe) -> Tuple[bool, str]:
    """
    Проверка TCP‑доступности через туннель.
    Если задан bind_source_ip, пытаемся привязать исходный адрес.
    """
    start = now_ts()
    try:
        # Проверка корректности IP адресов
        if probe.bind_source_ip:
            ipaddress.ip_address(probe.bind_source_ip)

        loop = asyncio.get_running_loop()

        def _connect() -> None:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(probe.connect_timeout_seconds)
            with contextlib.closing(s):
                if probe.bind_source_ip:
                    s.bind((probe.bind_source_ip, 0))
                s.connect((probe.host, probe.port))

        await loop.run_in_executor(None, _connect)
        return True, f"tcp ok in {now_ts() - start:.3f}s"
    except Exception as e:
        return False, f"tcp failed: {e!s}"


class WireGuardAdapter:
    @staticmethod
    async def check(
        iface: str,
        handshake_max_age_seconds: float,
        connect_probe: Optional[TCPProbe],
        timeout: float,
    ) -> CheckResult:
        t0 = now_ts()
        labels = {"tunnel": iface, "type": "wireguard"}
        ok = False
        reason = ""
        details: Dict[str, Any] = {}

        # Проверяем наличие интерфейса
        rc, _, _ = await run_cmd(["wg", "show", iface], timeout=timeout)
        if rc != 0:
            reason = "wg interface not found or down"
            duration = now_ts() - t0
            return CheckResult(iface, False, reason, {"step": "iface"}, duration)

        # Давность handshake: берём минимальную среди пиров (считаем установлено, если хоть один пир активен)
        rc, out, err = await run_cmd(["wg", "show", iface, "latest-handshakes"], timeout=timeout)
        if rc != 0:
            reason = f"wg latest-handshakes failed: {err.strip()}"
            duration = now_ts() - t0
            return CheckResult(iface, False, reason, {"step": "handshake"}, duration)

        latest_ages: List[float] = []
        now_epoch = int(time.time())
        for line in out.strip().splitlines():
            parts = line.strip().split()
            if len(parts) != 2:
                continue
            try:
                ts_epoch = int(parts[1])
                if ts_epoch == 0:
                    continue
                age = float(max(0, now_epoch - ts_epoch))
                latest_ages.append(age)
            except ValueError:
                continue

        if not latest_ages:
            reason = "no recent handshakes"
            details["handshake_age_seconds"] = None
            duration = now_ts() - t0
            return CheckResult(iface, False, reason, details, duration)

        min_age = min(latest_ages)
        details["handshake_age_seconds"] = min_age
        ok = min_age <= handshake_max_age_seconds
        reason = "handshake fresh" if ok else f"handshake too old: {min_age:.0f}s"

        # Метрики по трафику (по возможности)
        rc, trans_out, _ = await run_cmd(["wg", "show", iface, "transfer"], timeout=timeout)
        if rc == 0:
            # Формат: "<pubkey>\t<rx_bytes>\t<tx_bytes>"
            rx_total = 0
            tx_total = 0
            for line in trans_out.strip().splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        rx_total += int(parts[1])
                        tx_total += int(parts[2])
                    except ValueError:
                        pass
            details["rx_bytes_total"] = rx_total
            details["tx_bytes_total"] = tx_total

        # Дополнительная TCP‑проверка
        if ok and connect_probe:
            tcp_ok, tcp_reason = await tcp_connect_check(connect_probe)
            details["tcp_probe"] = tcp_reason
            ok = ok and tcp_ok
            if not tcp_ok:
                reason = "tcp probe failed"

        duration = now_ts() - t0
        return CheckResult(iface, ok, reason, details, duration)


class OpenVPNAdapter:
    @staticmethod
    async def check(
        name: str,
        systemd_service: Optional[str],
        status_file: Optional[str],
        connect_probe: Optional[TCPProbe],
        timeout: float,
    ) -> CheckResult:
        t0 = now_ts()
        labels = {"tunnel": name, "type": "openvpn"}
        ok = False
        reason = ""
        details: Dict[str, Any] = {}

        if systemd_service:
            rc, out, err = await run_cmd(["systemctl", "is-active", "--quiet", systemd_service], timeout=timeout)
            if rc == 0:
                ok = True
                reason = "service active"
            else:
                ok = False
                reason = "service not active"

        if status_file:
            try:
                with open(status_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                # Примитивный признак установления
                if "CONNECTED,SUCCESS" in content or "CLIENT_LIST" in content or "ROUTING_TABLE" in content:
                    ok = True
                    reason = "status connected"
                details["status_file_mtime"] = os.path.getmtime(status_file)
            except FileNotFoundError:
                ok = False
                reason = "status file missing"

        if connect_probe:
            tcp_ok, tcp_reason = await tcp_connect_check(connect_probe)
            details["tcp_probe"] = tcp_reason
            ok = ok and tcp_ok if (systemd_service or status_file) else tcp_ok
            if not tcp_ok:
                reason = "tcp probe failed"

        duration = now_ts() - t0
        return CheckResult(name, ok, reason, details, duration)


class IpsecAdapter:
    @staticmethod
    async def check(
        connection: str,
        connect_probe: Optional[TCPProbe],
        timeout: float,
    ) -> CheckResult:
        t0 = now_ts()
        labels = {"tunnel": connection, "type": "ipsec"}
        ok = False
        reason = ""
        details: Dict[str, Any] = {}

        # strongSwan: ipsec status <conn> -> содержит ESTABLISHED
        rc, out, err = await run_cmd(["ipsec", "status", connection], timeout=timeout)
        if rc == 0 and "ESTABLISHED" in out.upper():
            ok = True
            reason = "ipsec established"
        else:
            # swanctl вариант
            rc2, out2, _ = await run_cmd(["swanctl", "--list-sas"], timeout=timeout)
            if rc2 == 0 and connection in out2 and ("INSTALLED" in out2 or "ESTABLISHED" in out2):
                ok = True
                reason = "swanctl installed"
            else:
                ok = False
                reason = "no established SA"

        if connect_probe:
            tcp_ok, tcp_reason = await tcp_connect_check(connect_probe)
            details["tcp_probe"] = tcp_reason
            ok = ok and tcp_ok if reason != "no established SA" else tcp_ok
            if not tcp_ok:
                reason = "tcp probe failed"

        duration = now_ts() - t0
        return CheckResult(connection, ok, reason, details, duration)


class GenericAdapter:
    @staticmethod
    async def check(name: str, connect_probe: Optional[TCPProbe], timeout: float) -> CheckResult:
        t0 = now_ts()
        if not connect_probe:
            return CheckResult(name, False, "no probe configured", {}, now_ts() - t0)
        ok, tcp_reason = await tcp_connect_check(connect_probe)
        details = {"tcp_probe": tcp_reason}
        return CheckResult(name, ok, "ok" if ok else "tcp probe failed", details, now_ts() - t0)


# ========= ОРКЕСТРАЦИЯ ПРОВЕРОК И МЕТРИК =========


class Monitor:
    def __init__(self, cfg: Config, registry: MetricsRegistry) -> None:
        self.cfg = cfg
        self.registry = registry

    async def check_tunnel(self, t: Tunnel) -> CheckResult:
        try:
            if t.type == "wireguard":
                if not t.interface:
                    return CheckResult(t.name, False, "missing interface", {}, 0.0)
                return await WireGuardAdapter.check(
                    iface=t.interface,
                    handshake_max_age_seconds=self.cfg.handshake_max_age_seconds,
                    connect_probe=t.tcp_probe,
                    timeout=self.cfg.connect_timeout_seconds,
                )
            if t.type == "openvpn":
                return await OpenVPNAdapter.check(
                    name=t.name,
                    systemd_service=t.systemd_service,
                    status_file=t.status_file,
                    connect_probe=t.tcp_probe,
                    timeout=self.cfg.connect_timeout_seconds,
                )
            if t.type == "ipsec":
                if not t.connection:
                    return CheckResult(t.name, False, "missing connection", {}, 0.0)
                return await IpsecAdapter.check(
                    connection=t.connection,
                    connect_probe=t.tcp_probe,
                    timeout=self.cfg.connect_timeout_seconds,
                )
            if t.type == "generic":
                return await GenericAdapter.check(
                    name=t.name, connect_probe=t.tcp_probe, timeout=self.cfg.connect_timeout_seconds
                )
            return CheckResult(t.name, False, f"unknown type {t.type}", {}, 0.0)
        except ExecError as e:
            return CheckResult(t.name, False, f"exec error: {e!s}", {}, 0.0)
        except Exception as e:
            log.exception("unexpected error on tunnel %s", t.name)
            return CheckResult(t.name, False, f"exception: {e!s}", {}, 0.0)

    def export_metrics(self, r: CheckResult, t: Tunnel) -> None:
        labels = {"tunnel": t.name, "type": t.type}
        self.registry.gauge_set("vpn_tunnel_up", 1.0 if r.ok else 0.0, labels)
        self.registry.gauge_set("vpn_tunnel_check_duration_seconds", r.duration_seconds, labels)
        if "handshake_age_seconds" in r.details and r.details["handshake_age_seconds"] is not None:
            self.registry.gauge_set(
                "vpn_tunnel_handshake_age_seconds", float(r.details["handshake_age_seconds"]), labels
            )
        if "rx_bytes_total" in r.details:
            self.registry.gauge_set("vpn_tunnel_rx_bytes_total", float(r.details["rx_bytes_total"]), labels)
        if "tx_bytes_total" in r.details:
            self.registry.gauge_set("vpn_tunnel_tx_bytes_total", float(r.details["tx_bytes_total"]), labels)
        if not r.ok:
            self.registry.counter_inc("vpn_tunnel_failures", 1.0, labels | {"reason": r.reason})

    async def run_once(self) -> Tuple[int, List[CheckResult]]:
        results = await asyncio.gather(*(self.check_tunnel(t) for t in self.cfg.tunnels))
        # Экспорт метрик и логирование
        worst = 0  # 0=OK, 2=DEGRADED, 3=DOWN
        for t, r in zip(self.cfg.tunnels, results):
            self.export_metrics(r, t)
            level = logging.INFO if r.ok else logging.ERROR
            log.log(level, "tunnel=%s type=%s ok=%s reason=%s details=%s", t.name, t.type, r.ok, r.reason, r.details)
            if not r.ok:
                worst = max(worst, 3)
        return worst, list(results)

    async def run_forever(self, stop_event: asyncio.Event) -> int:
        while not stop_event.is_set():
            t0 = now_ts()
            rc, _ = await self.run_once()
            dt_spent = now_ts() - t0
            sleep_left = max(0.0, self.cfg.interval_seconds - dt_spent)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=sleep_left)
            except asyncio.TimeoutError:
                pass
        return 0


# ========= CLI =========


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="vpn_monitor", description="VPN health monitor with Prometheus metrics")
    p.add_argument("--config", help="path to YAML or JSON config", default=None)
    p.add_argument("--interval", type=float, help="override interval seconds", default=None)
    p.add_argument("--once", action="store_true", help="run single check and exit")
    p.add_argument("--metrics-port", type=int, default=None, help="override metrics port")
    p.add_argument("--metrics-host", type=str, default=None, help="override metrics host")
    p.add_argument("--log-level", type=str, default=os.getenv("LOG_LEVEL", "INFO"))
    p.add_argument("--log-json", action="store_true", default=os.getenv("LOG_JSON", "0") == "1")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    setup_logging(args.log_level, args.log_json)

    try:
        cfg = load_config(args.config)
    except Exception as e:
        log.error("config error: %s", e)
        return 1

    if args.interval is not None:
        cfg.interval_seconds = float(args.interval)
    if args.metrics_port is not None:
        cfg.metrics_port = int(args.metrics_port)
    if args.metrics_host is not None:
        cfg.metrics_host = str(args.metrics_host)

    registry = MetricsRegistry()
    if cfg.metrics_enabled:
        start_metrics_http(cfg.metrics_host, cfg.metrics_port, registry)

    monitor = Monitor(cfg, registry)

    async def _async_main() -> int:
        stop_event = asyncio.Event()

        def _handle_signal(signum: int, frame: Any) -> None:
            log.info("received signal %s, stopping", signum)
            stop_event.set()

        for s in (signal.SIGINT, signal.SIGTERM):
            signal.signal(s, _handle_signal)

        if args.once:
            rc, _ = await monitor.run_once()
            return rc
        else:
            await monitor.run_forever(stop_event)
            return 0

    try:
        return asyncio.run(_async_main())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
