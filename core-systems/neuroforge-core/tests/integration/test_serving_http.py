# neuroforge-core/tests/integration/test_serving_http.py
# -*- coding: utf-8 -*-
"""
Интеграционные тесты HTTP-сервинга NeuroForge.

Конфигурация через переменные окружения:
  NF_TEST_BASE_URL      — базовый URL уже запущенного сервиса (например, http://127.0.0.1:8080)
  NF_TEST_SPAWN_APP     — "1" чтобы поднять локально uvicorn (если BASE_URL не задан)
  NF_TEST_APP           — путь к фабрике ASGI-приложения "pkg.module:create_app" (для спавна)
  NF_TEST_TIMEOUT_S     — таймаут HTTP-запросов, сек (по умолчанию 5)
  NF_TEST_HEALTH_P95_MS — допустимый p95 латентности /health, мс (по умолчанию 150)
  NF_TEST_METRICS_REQ   — "1" чтобы строго требовать /metrics (иначе soft-optional)

Зависимости:
  pytest, httpx, (опц.) uvicorn, fastapi/starlette — только при NF_TEST_SPAWN_APP=1.
"""

from __future__ import annotations

import json
import os
import random
import re
import signal
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict, Iterable, Optional
from urllib.parse import urljoin

import pytest
import httpx

# ---------- Константы и конфиг ----------
DEFAULT_BASE_URL = os.getenv("NF_TEST_BASE_URL", "").strip()
SPAWN_APP = os.getenv("NF_TEST_SPAWN_APP", "0").strip() == "1"
APP_FACTORY = os.getenv("NF_TEST_APP", "neuroforge.serving.app:create_app")
TIMEOUT_S = float(os.getenv("NF_TEST_TIMEOUT_S", "5"))
P95_HEALTH_MS = int(os.getenv("NF_TEST_HEALTH_P95_MS", "150"))
METRICS_REQUIRED = os.getenv("NF_TEST_METRICS_REQ", "0").strip() == "1"


# ---------- Утилиты ----------
def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http_ready(base_url: str, path: str = "/health", timeout_s: float = 10.0) -> None:
    deadline = time.time() + timeout_s
    last_err: Optional[Exception] = None
    while time.time() < deadline:
        try:
            with httpx.Client(timeout=TIMEOUT_S) as c:
                r = c.get(urljoin(base_url, path))
                if r.status_code < 500:
                    return
        except Exception as e:  # noqa: BLE001
            last_err = e
        time.sleep(0.2)
    raise TimeoutError(f"Service not ready at {base_url}{path}: {last_err}")


@contextmanager
def _spawn_uvicorn(app_factory: str):
    """
    Запускает uvicorn для 'pkg.module:create_app' на свободном порту.
    Ожидает готовность по /health. Возвращает (proc, base_url).
    """
    try:
        import uvicorn  # noqa: F401
    except Exception as e:  # pragma: no cover
        pytest.skip(f"uvicorn не установлен: {e}")

    port = _find_free_port()
    host = "127.0.0.1"
    base_url = f"http://{host}:{port}"
    # Пробуем динамический reload отключить, workers=1 для стабильности
    cmd = [
        sys.executable, "-m", "uvicorn",
        f"{app_factory}",
        "--host", host,
        "--port", str(port),
        "--workers", "1",
        "--timeout-keep-alive", "5",
        "--no-access-log",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)  # noqa: S603
    try:
        _wait_http_ready(base_url, "/health", timeout_s=15)
        yield proc, base_url
    finally:
        if proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception:
                proc.kill()


# ---------- Фикстуры ----------
@pytest.fixture(scope="session")
def base_url() -> str:
    """
    База для всех тестов.
    - Если указан NF_TEST_BASE_URL — используем его.
    - Иначе, если NF_TEST_SPAWN_APP=1 — спавним uvicorn для APP_FACTORY.
    - Иначе: skip.
    """
    if DEFAULT_BASE_URL:
        return DEFAULT_BASE_URL.rstrip("/") + "/"
    if SPAWN_APP:
        with _spawn_uvicorn(APP_FACTORY) as (proc, url):
            # Сохраняем контекст на время сессии
            yield url.rstrip("/") + "/"
            # Процесс гасящийся в менеджере
            return
    pytest.skip("Не задан NF_TEST_BASE_URL и не включён NF_TEST_SPAWN_APP=1")


@pytest.fixture(scope="session")
def client(base_url: str) -> Iterable[httpx.Client]:
    headers = {
        "User-Agent": "NeuroForge-Tests/1.0",
        # Демонстрация traceparent (W3C) — сервер может проигнорировать
        "traceparent": _mk_traceparent(),
    }
    with httpx.Client(base_url=base_url, headers=headers, timeout=TIMEOUT_S) as c:
        yield c


def _mk_traceparent() -> str:
    def rnd_hex(n: int) -> str:
        rnd = random.getrandbits(n * 4)
        return f"{rnd:0{n}x}"
    return f"00-{rnd_hex(32)}-{rnd_hex(16)}-01"


# ---------- Хелперы проверок ----------
def _is_json_response(r: httpx.Response) -> bool:
    ctype = r.headers.get("content-type", "")
    return "application/json" in ctype or "application/problem+json" in ctype


def _assert_security_headers(r: httpx.Response) -> None:
    # Базовый набор. Не все API ставят HSTS/Frame-Options — допускаем xfail.
    xcto = r.headers.get("x-content-type-options", "").lower()
    assert xcto == "nosniff", "Ожидается X-Content-Type-Options=nosniff"

    # Остальное — мягкие ожидания, не падать жёстко:
    csp = r.headers.get("content-security-policy")
    xfo = r.headers.get("x-frame-options")
    hsts = r.headers.get("strict-transport-security")
    if csp is None or xfo is None:
        pytest.xfail("Опциональные заголовки безопасности (CSP/X-Frame-Options) отсутствуют")
    if r.url.scheme == "https" and hsts is None:
        pytest.xfail("HSTS желательно для HTTPS")


def _pick_existing_path(client: httpx.Client, paths: list[str]) -> Optional[str]:
    for p in paths:
        resp = client.get(p)
        if resp.status_code < 500:
            return p
    return None


# ---------- Тесты ----------
@pytest.mark.integration
def test_health_ok(client: httpx.Client):
    r = client.get("/health")
    assert r.status_code == 200, f"/health должен возвращать 200, получено {r.status_code}"

    # Допускаем разные форматы, но JSON предпочтителен
    if _is_json_response(r):
        data = r.json()
        assert isinstance(data, dict), "Тело /health должно быть JSON-объектом"
        # Мягкие ключи: status/version/uptime — опционально
        if "status" in data:
            assert str(data["status"]).lower() in {"ok", "ready", "healthy"}
    else:
        text = r.text.strip().lower()
        assert "ok" in text or "healthy" in text


@pytest.mark.integration
def test_readiness_optional(client: httpx.Client):
    path = _pick_existing_path(client, ["/ready", "/live", "/readiness"])
    if not path:
        pytest.xfail("Маршрут readiness отсутствует")
    r = client.get(path)
    assert r.status_code in (200, 204), f"{path} должен возвращать 2xx/204"
    # Разрешаем пустой ответ для 204


@pytest.mark.integration
def test_metrics_prometheus(client: httpx.Client):
    r = client.get("/metrics")
    if r.status_code == 404:
        if METRICS_REQUIRED:
            pytest.fail("/metrics обязателен по NF_TEST_METRICS_REQ=1")
        pytest.xfail("Метрики Prometheus отсутствуют")
    assert r.status_code == 200
    ctype = r.headers.get("content-type", "")
    assert "text/plain" in ctype or "prometheus" in ctype.lower()
    body = r.text
    # Признаки формата Prometheus
    assert "# HELP" in body or "# TYPE" in body or "process_cpu_seconds_total" in body or "python_info" in body


@pytest.mark.integration
def test_predict_minimal_optional(client: httpx.Client):
    # Наиболее частый контракт: POST /v1/predict с JSON {"inputs": ...}
    payload = {"inputs": [[0.1, 0.2, 0.3]]}
    r = client.post("/v1/predict", json=payload)
    if r.status_code == 404:
        pytest.xfail("Контур инференса /v1/predict отсутствует")
    assert r.status_code in (200, 202), f"Ожидается 200/202, получено {r.status_code}"
    assert _is_json_response(r), "Ответ инференса должен быть JSON"
    data = r.json()
    # Допускаем разные ключи: outputs/predictions/result
    keys = set(map(str.lower, data.keys()))
    assert any(k in keys for k in {"outputs", "predictions", "result"}), "Нет поля с предсказаниями"
    # Латентность по заголовку Server-Timing (если есть)
    st = r.headers.get("server-timing", "")
    if st and "dur=" in st:
        # server-timing: trace;dur=12.3
        m = re.search(r"dur=([0-9]+(\.[0-9]+)?)", st)
        if m:
            dur_ms = float(m.group(1))
            assert dur_ms < 1000, f"Инференс слишком медленный: {dur_ms}ms"


@pytest.mark.integration
def test_trace_context_propagation_soft(client: httpx.Client):
    # Сервер может пробрасывать trace-id либо в заголовок, либо в тело/логи. Здесь — мягкая проверка.
    traceparent = _mk_traceparent()
    r = client.get("/health", headers={"traceparent": traceparent})
    assert r.status_code == 200
    # Если сервер отражает traceparent — проверим формат
    echoed = r.headers.get("traceparent") or r.headers.get("x-traceparent")
    if echoed:
        assert re.fullmatch(r"00-[0-9a-f]{32}-[0-9a-f]{16}-0[01]", echoed) is not None


@pytest.mark.integration
def test_security_headers_base(client: httpx.Client):
    # Проверяем на /health — как на самом простом эндпоинте
    r = client.get("/health")
    _assert_security_headers(r)


@pytest.mark.integration
def test_cors_preflight_optional(client: httpx.Client):
    # CORS preflight для /v1/predict
    headers = {
        "Origin": "https://example.com",
        "Access-Control-Request-Method": "POST",
    }
    r = client.options("/v1/predict", headers=headers)
    if r.status_code in (404, 405):
        pytest.xfail("CORS/OPTIONS не настроен для /v1/predict")
    assert r.status_code in (200, 204)
    allow_origin = r.headers.get("access-control-allow-origin")
    if allow_origin is None:
        pytest.xfail("Отсутствует Access-Control-Allow-Origin")


@pytest.mark.integration
def test_404_contract(client: httpx.Client):
    r = client.get("/definitely-not-exists-404")
    assert r.status_code == 404
    # Желательно JSON-ошибка с problem details, но не обязательно
    if _is_json_response(r):
        body = r.json()
        assert isinstance(body, dict)
        # опциональные поля: title, status, detail
        if "status" in body:
            assert int(body["status"]) == 404


# ---------- Производительность ----------
@pytest.mark.perf
def test_health_latency_p95(client: httpx.Client):
    n = 30
    durs = []
    for _ in range(n):
        t0 = time.perf_counter()
        r = client.get("/health")
        t1 = time.perf_counter()
        assert r.status_code == 200
        durs.append((t1 - t0) * 1000.0)
        # лёгкая пауза, чтобы не вызывать rate limiters
        time.sleep(0.01)

    p95 = _percentile(durs, 95.0)
    assert p95 <= P95_HEALTH_MS, f"/health p95 {p95:.1f}ms превышает порог {P95_HEALTH_MS}ms"


# ---------- Вспомогательные функции ----------
def _percentile(values, q: float) -> float:
    xs = sorted(values)
    if not xs:
        return 0.0
    k = (len(xs) - 1) * (q / 100.0)
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    if f == c:
        return xs[int(k)]
    return xs[f] + (xs[c] - xs[f]) * (k - f)


# ---------- Маркеры по умолчанию ----------
def pytest_configure(config):
    config.addinivalue_line("markers", "integration: интеграционные тесты HTTP")
    config.addinivalue_line("markers", "perf: тесты производительности")
