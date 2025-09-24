# cybersecurity-core/tests/e2e/test_cyber_pipeline_e2e.py
# -*- coding: utf-8 -*-

import contextlib
import http.server
import io
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Tuple

import pytest


# -------------------------------
# УТИЛИТЫ ДЛЯ РАЗРЕШЕНИЯ ПУТЕЙ
# -------------------------------

def _resolve_scan_assets_path() -> Path | None:
    """
    Пытается найти исполняемый файл сканера:
    1) через импорт модуля cybersecurity_core.cli.tools.scan_assets
    2) по типовым относительным путям от текущего файла.
    Возвращает Path или None (если не найден).
    """
    # 1) Попытка импорта как пакета
    try:
        import importlib
        mod = importlib.import_module("cybersecurity_core.cli.tools.scan_assets")
        p = Path(mod.__file__).resolve()
        if p.exists():
            return p
    except Exception:
        pass

    # 2) Типовые расположения относительно этого файла
    here = Path(__file__).resolve()
    candidates = [
        here.parents[3] / "cybersecurity-core" / "cli" / "tools" / "scan_assets.py",
        here.parents[2] / "cli" / "tools" / "scan_assets.py",
        here.parent.parent / "cli" / "tools" / "scan_assets.py",
    ]
    for c in candidates:
        c = c.resolve()
        if c.exists():
            return c
    return None


# -----------------------------------
# ЛОКАЛЬНЫЕ ТЕСТОВЫЕ СЕТЕВЫЕ СЕРВИСЫ
# -----------------------------------

class _QuietHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: N802  (сигнатура stdlib)
        pass  # подавляем шум логов в тестах


class _ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


class _BannerTCPHandler(socketserver.BaseRequestHandler):
    BANNER = b"HELLO_FROM_TEST_SERVER\r\n"

    def handle(self) -> None:
        try:
            # простая приветственная строка и закрытие
            self.request.sendall(self.BANNER)
            # опционально прочитать немного для корректного закрытия
            with contextlib.suppress(Exception):
                self.request.recv(1024)
        except Exception:
            pass


@contextlib.contextmanager
def run_http_server(bind: str = "127.0.0.1", port: int = 0):
    """
    Поднимает минимальный HTTP-сервер в отдельном треде.
    Возвращает фактический порт.
    """
    server = _ThreadingHTTPServer((bind, port), _QuietHTTPHandler)
    actual_port = server.server_address[1]
    th = threading.Thread(target=server.serve_forever, name="HTTPServer", daemon=True)
    th.start()
    try:
        yield actual_port
    finally:
        with contextlib.suppress(Exception):
            server.shutdown()
            server.server_close()
        th.join(timeout=3)


@contextlib.contextmanager
def run_tcp_banner_server(bind: str = "127.0.0.1", port: int = 0):
    """
    Поднимает TCP-сервер, отдающий краткий баннер.
    Возвращает фактический порт.
    """
    server = _ThreadingTCPServer((bind, port), _BannerTCPHandler)
    actual_port = server.server_address[1]
    th = threading.Thread(target=server.serve_forever, name="TCPServer", daemon=True)
    th.start()
    try:
        yield actual_port
    finally:
        with contextlib.suppress(Exception):
            server.shutdown()
            server.server_close()
        th.join(timeout=3)


# -------------------------------
# ВСПОМОГАТЕЛЬНЫЕ ПРОЦЕДУРЫ CLI
# -------------------------------

def _run_scan_assets(
    scan_path: Path,
    targets: List[str],
    ports: List[int],
    out_dir: Path,
    enable_http: bool = True,
    enable_tls: bool = False,
    timeout_s: float = 3.0,
    concurrency: int = 50,
) -> Tuple[Path, Path, str]:
    """
    Запускает scan_assets.py как подпроцесс и возвращает пути к JSONL/CSV и stdout.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl = out_dir / "results.jsonl"
    csv = out_dir / "results.csv"

    args = [
        sys.executable,
        str(scan_path),
        "--targets",
        ",".join(targets),
        "--ports",
        ",".join(map(str, ports)),
        "--concurrency",
        str(concurrency),
        "--timeout",
        str(timeout_s),
        "--jsonl",
        str(jsonl),
        "--csv",
        str(csv),
        "--log-level",
        "INFO",
    ]
    if enable_http:
        args.append("--enable-http")
    if enable_tls:
        args.append("--enable-tls")

    # В качестве рабочего каталога используем директорию скрипта — он самодостаточен (stdlib only)
    env = os.environ.copy()
    proc = subprocess.run(
        args,
        cwd=str(scan_path.parent),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=60,
        check=True,
    )
    return jsonl, csv, proc.stdout


def _read_jsonl(p: Path) -> List[Dict]:
    rows: List[Dict] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


# ----------------------
# СКВОЗНЫЕ E2E-СЦЕНАРИИ
# ----------------------

@pytest.mark.e2e
def test_scan_assets_end_to_end_local_services(tmp_path: Path):
    """
    Сквозная проверка:
      1) Поднимаем локальные TCP и HTTP сервисы
      2) Запускаем реальный CLI-сканер с этими портами
      3) Валидируем JSONL/CSV, находим строки с 127.0.0.1 и нужными портами
      4) Проверяем флаги reachability и базовые поля HTTP
    """
    scan_path = _resolve_scan_assets_path()
    if not scan_path or not scan_path.exists():
        pytest.skip("scan_assets.py not found")

    with run_tcp_banner_server() as tcp_port, run_http_server() as http_port:
        jsonl, csv, stdout = _run_scan_assets(
            scan_path=scan_path,
            targets=["127.0.0.1"],
            ports=[tcp_port, http_port],
            out_dir=tmp_path / "out",
            enable_http=True,
            enable_tls=False,
            timeout_s=3.0,
            concurrency=20,
        )

        assert jsonl.exists(), f"JSONL not found. STDOUT:\n{stdout}"
        assert csv.exists(), f"CSV not found. STDOUT:\n{stdout}"

        rows = _read_jsonl(jsonl)
        assert len(rows) >= 2, f"Expected at least 2 rows (tcp+http), got {len(rows)}. STDOUT:\n{stdout}"

        # Ищем записи по портам
        by_port = {int(r["port"]): r for r in rows if r.get("ip") in {"127.0.0.1", "::1"}}
        assert tcp_port in by_port, f"No TCP row for port {tcp_port}. Rows: {list(by_port.keys())}"
        assert http_port in by_port, f"No HTTP row for port {http_port}. Rows: {list(by_port.keys())}"

        tcp_row = by_port[tcp_port]
        http_row = by_port[http_port]

        # TCP-проверки
        assert tcp_row["tcp"]["reachable"] is True
        # Баннер TCP сервер может быть принят либо tcp_probe, либо пуст — это не критично.
        assert "latency_ms" in tcp_row["tcp"] and tcp_row["tcp"]["latency_ms"] is not None

        # HTTP-проверки (HEAD /)
        # SimpleHTTPRequestHandler обычно отвечает 200, но допускаем вариативность; главное — статус присутствует.
        assert http_row["tcp"]["reachable"] is True
        if http_row.get("http"):
            status = http_row["http"].get("status")
            assert isinstance(status, int) and 100 <= status < 600

        # Общие поля
        for row in (tcp_row, http_row):
            assert row["host"] in {"127.0.0.1", "localhost"}
            assert isinstance(row["ts"], str) and row["ts"]
            assert row.get("error") in (None, "cancelled") or isinstance(row["error"], str)


@pytest.mark.e2e
def test_cli_version_flag(tmp_path: Path):
    """
    smoke-проверка флага --version
    """
    scan_path = _resolve_scan_assets_path()
    if not scan_path or not scan_path.exists():
        pytest.skip("scan_assets.py not found")

    args = [sys.executable, str(scan_path), "--version"]
    proc = subprocess.run(
        args,
        cwd=str(scan_path.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
        check=True,
    )
    out = proc.stdout.strip()
    # Ожидаем строку формата "scan_assets X.Y.Z"
    assert "scan_assets" in out and any(ch.isdigit() for ch in out), f"Unexpected version output: {out}"


@pytest.mark.e2e
def test_pipeline_with_optional_risk_scoring(tmp_path: Path):
    """
    Расширенный сквозной тест (опционально):
      - Парсит результаты сканера
      - Агрегирует простые сигналы для RiskScorer
      - Выполняет скоринг и проверяет диапазон/тип
    Пропускается, если модуль RiskScorer отсутствует.
    """
    # импортируем RiskScorer опционально
    try:
        from cybersecurity_core import risk_scoring as _rs  # type: ignore
    except Exception:
        pytest.skip("RiskScorer module not available")

    scan_path = _resolve_scan_assets_path()
    if not scan_path or not scan_path.exists():
        pytest.skip("scan_assets.py not found")

    with run_http_server() as http_port:
        # сканируем только HTTP порт
        jsonl, _csv, stdout = _run_scan_assets(
            scan_path=scan_path,
            targets=["127.0.0.1"],
            ports=[http_port],
            out_dir=tmp_path / "out2",
            enable_http=True,
            enable_tls=False,
            timeout_s=3.0,
            concurrency=10,
        )

        rows = _read_jsonl(jsonl)
        # агрегируем сигналы по «хосту»
        reachable = [r for r in rows if r.get("ip") in {"127.0.0.1", "::1"} and r.get("tcp", {}).get("reachable")]
        open_ports = len({int(r["port"]) for r in reachable})
        internet_exposed = False  # локальный стенд
        asset_criticality = 0.1   # демо-значение для теста
        vuln_count = 0
        cvss_base = 0.0
        anomalous_activity = 0.0
        last_patch_age_days = 0

        signals = {
            "cvss_base": cvss_base,
            "vuln_count": vuln_count,
            "exploit_available": False,
            "internet_exposed": internet_exposed,
            "asset_criticality": asset_criticality,
            "open_ports": open_ports,
            "anomalous_activity": anomalous_activity,
            "last_patch_age_days": last_patch_age_days,
        }

        scorer = _rs.RiskScorer()
        payload = scorer.score(signals)
        assert isinstance(payload, dict)
        assert "score" in payload and "severity" in payload
        assert 0.0 <= float(payload["score"]) <= 100.0
        assert payload["severity"] in {"Informational", "Low", "Medium", "High", "Critical"}
