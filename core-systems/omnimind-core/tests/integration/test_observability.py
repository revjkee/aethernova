# omnimind-core/tests/integration/test_observability.py
from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import socket
import sys
import time
import urllib.request
from typing import Optional

import pytest

# Тестируем модуль bootstrap, ранее предоставленный в ops/omnimind/bootstrap.py
# Предполагается, что PYTHONPATH указывает на корень проекта.
from ops.omnimind.bootstrap import bootstrap, BootstrapContext


def _free_port() -> int:
    """Возвращает свободный TCP-порт (localhost)."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http_get(url: str, timeout: float = 2.0) -> tuple[int, bytes, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "omni-test/1"})
    with contextlib.closing(urllib.request.urlopen(req, timeout=timeout)) as resp:
        return resp.status, resp.read(), resp.getheader("Content-Type") or ""


def _wait_until(fn, timeout: float = 3.0, interval: float = 0.05, desc: str = "condition"):
    start = time.monotonic()
    last = None
    while True:
        ok, last = fn()
        if ok:
            return
        if time.monotonic() - start > timeout:
            raise AssertionError(f"timeout waiting for {desc}; last={last}")
        time.sleep(interval)


@pytest.fixture(scope="function")
def ctx_with_observability(monkeypatch) -> BootstrapContext:
    """
    Поднимает bootstrap-контекст на свободных портах.
    Метрики включены, трейсинг выключен, логи — JSON в stdout.
    """
    health_port = _free_port()
    metrics_port = _free_port()

    # Минимальный конфиг через переменные окружения (bootstrap читает OMNI__* оверрайды)
    monkeypatch.setenv("OMNI__server__bind_host", "127.0.0.1")
    monkeypatch.setenv("OMNI__server__port", str(health_port))

    # Логирование в JSON
    monkeypatch.setenv("OMNI__logging__level", "INFO")
    monkeypatch.setenv("OMNI__logging__json", "true")

    # Метрики Prometheus
    monkeypatch.setenv("OMNI__metrics__enabled", "true")
    monkeypatch.setenv("OMNI__metrics__port", str(metrics_port))

    # Трейсинг выключен
    monkeypatch.setenv("OMNI__tracing__enabled", "false")

    # Поднятие bootstrap
    ctx = bootstrap(service_name="omni-test", validate=False)
    yield ctx

    # Грейсфул shutdown
    with contextlib.suppress(Exception):
        ctx.shutdown()


def test_health_endpoints_liveness_readiness(ctx_with_observability: BootstrapContext):
    # Выясняем фактический порт health-сервера (если был 0, HTTPServer назначает сам)
    srv = ctx_with_observability.health.server
    assert srv is not None, "health server must be initialized"
    host, port = srv.server_address
    base = f"http://{host}:{port}"

    # /healthz/live должен быть готов сразу
    status, body, ctype = _http_get(f"{base}/healthz/live")
    assert status == 200, f"live endpoint should be 200, got {status}"
    assert "application/json" in ctype
    doc = json.loads(body.decode("utf-8"))
    assert doc.get("status") == "live"

    # /healthz/ready до ready() должен быть 503
    status, _, _ = _http_get(f"{base}/healthz/ready")
    assert status == 503

    # Переводим в ready и проверяем 200
    ctx_with_observability.ready()

    def _ready_ok():
        try:
            st, _, _ = _http_get(f"{base}/healthz/ready")
            return (st == 200), st
        except Exception as e:
            return False, str(e)

    _wait_until(_ready_ok, timeout=2.0, desc="/healthz/ready==200")


def test_prometheus_metrics_exposed(ctx_with_observability: BootstrapContext):
    # Если prometheus_client не установлен, тест корректно пропускается
    prom_avail = "prometheus_client" in sys.modules or _prometheus_installed()
    if not prom_avail:
        pytest.skip("prometheus_client is not installed in test environment")

    # Получаем порт метрик из окружения, он был забит в фикстуре
    metrics_port = int(os.environ.get("OMNI__metrics__port", "0"))
    assert metrics_port > 0

    base = f"http://127.0.0.1:{metrics_port}"

    def _metrics_ok():
        try:
            st, body, ctype = _http_get(f"{base}/", timeout=2.0)
            if st != 200:
                return False, st
            text = body.decode("utf-8", errors="ignore")
            # Проверяем, что это текст Prometheus: есть HELP/TYPE строки
            return ("# HELP" in text or "# TYPE" in text) and "process_cpu_seconds_total" in text or "python_info" in text, len(text)
        except Exception as e:
            return False, str(e)

    _wait_until(_metrics_ok, timeout=3.0, desc="prometheus scrape page")


def _prometheus_installed() -> bool:
    try:
        import prometheus_client  # noqa: F401
        return True
    except Exception:
        return False


def test_tracing_disabled_safely(ctx_with_observability: BootstrapContext):
    # При отключённом OTEL провайдер должен быть None и тест не должен падать
    tr = ctx_with_observability.tracing
    assert getattr(tr, "provider", None) is None


def test_json_logging_to_stdout(ctx_with_observability: BootstrapContext, capsys: pytest.CaptureFixture[str]):
    """
    Проверяет, что логгер выводит JSON-строки с ожидаемыми полями.
    """
    logger = ctx_with_observability.logger
    # Логируем сообщение; capsys перехватит stdout
    logger.info("observability_test_event", extra={"test_key": "value123"})

    # Дадим логгерам шанс сбросить буфер
    time.sleep(0.05)

    out = capsys.readouterr().out.strip().splitlines()
    # На stdout должны быть строки логов; берём последнюю
    assert out, "no logs captured on stdout"
    last = out[-1]
    # Должен быть валидный JSON
    parsed = json.loads(last)
    # Проверяем базовые поля форматтера
    assert parsed.get("lvl") == "INFO"
    assert parsed.get("msg") == "observability_test_event"
    # Поле из extra
    assert parsed.get("test_key") == "value123"
    # Временная метка присутствует
    assert "ts" in parsed
