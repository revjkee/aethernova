# neuroforge-core/tests/e2e/test_train_to_serve_e2e.py
# E2E: train -> export -> serve -> health -> predict -> retrain -> predict drift
# Статус: UNVERIFIED — конкретные команды/эндпоинты вашей системы неизвестны. I cannot verify this.

from __future__ import annotations

import json
import os
import random
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Tuple
import contextlib
import pathlib

import pytest


# =========================
# Конфигурация через ENV
# =========================
ENV = {
    "TRAIN_CMD": os.getenv("NEUROFORGE_TRAIN_CMD", "").strip(),       # str | ""  (напр. "python -m train --out {model}")
    "EXPORT_CMD": os.getenv("NEUROFORGE_EXPORT_CMD", "").strip(),     # опц.
    "SERVE_CMD": os.getenv("NEUROFORGE_SERVE_CMD", "").strip(),       # опц.
    "SERVE_WORKDIR": os.getenv("NEUROFORGE_SERVE_CWD", "").strip(),   # опц.
    "HEALTH_URL": os.getenv("NEUROFORGE_HEALTH_URL", "").strip(),     # опц. (если используем внешний сервинг)
    "PREDICT_URL": os.getenv("NEUROFORGE_PREDICT_URL", "").strip(),   # опц.
    "SLA_P95_MS": int(os.getenv("NEUROFORGE_SLA_P95_MS", "5000")),    # SLA по задержке P95, по умолчанию 5с
    "STARTUP_TIMEOUT_S": float(os.getenv("NEUROFORGE_SERVE_STARTUP_TIMEOUT_S", "45.0")),  # ожидание старта сервера
    "PREDICT_REPEATS": int(os.getenv("NEUROFORGE_PREDICT_REPEATS", "7")),  # для оценки p95
}


# =========================
# Утилиты
# =========================
def _now_ms() -> int:
    return int(time.time() * 1000)

def _render_cmd(cmd: str, **kwargs: str) -> str:
    # Подставляем плейсхолдеры вида {model}, {export}, {port}
    return cmd.format(**kwargs)

def _run_cmd(cmd: str, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, timeout: Optional[float] = None) -> Tuple[int, str]:
    """
    Запускает команду в shell-режиме, возвращает (rc, stdout+stderr).
    """
    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)
    try:
        p = subprocess.Popen(cmd, cwd=cwd or None, env=proc_env, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out or ""
    except subprocess.TimeoutExpired:
        with contextlib.suppress(Exception):
            p.kill()
        return 124, f"TIMEOUT after {timeout}s"
    except Exception as e:
        return 1, f"ERROR: {e}"

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]

def _sleep_backoff(total_timeout_s: float, step_s: float = 0.25):
    """
    Итератор с паузами до истечения total_timeout_s.
    """
    start = time.time()
    while (time.time() - start) < total_timeout_s:
        time.sleep(step_s)
        yield


# =========================
# Fallback HTTP клиент (requests -> http.client)
# =========================
def _http_post_json(url: str, payload: Dict[str, Any], timeout: float = 5.0) -> Tuple[int, Dict[str, Any], float]:
    """
    Возвращает (status_code, json, latency_seconds)
    """
    t0 = time.time()
    try:
        import requests  # type: ignore
        r = requests.post(url, json=payload, timeout=timeout)
        dt = time.time() - t0
        try:
            return r.status_code, r.json(), dt
        except Exception:
            return r.status_code, {"_raw": r.text}, dt
    except Exception:
        # stdlib fallback
        from urllib.parse import urlparse
        import http.client
        parsed = urlparse(url)
        conn_cls = http.client.HTTPConnection if parsed.scheme == "http" else http.client.HTTPSConnection
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        conn = conn_cls(parsed.hostname, parsed.port, timeout=timeout)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        dt = time.time() - t0
        raw = resp.read()
        try:
            return resp.status, json.loads(raw.decode("utf-8")), dt
        except Exception:
            return resp.status, {"_raw": raw.decode("utf-8", errors="replace")}, dt

def _http_get(url: str, timeout: float = 5.0) -> int:
    try:
        import requests  # type: ignore
        r = requests.get(url, timeout=timeout)
        return r.status_code
    except Exception:
        from urllib.parse import urlparse
        import http.client
        parsed = urlparse(url)
        conn_cls = http.client.HTTPConnection if parsed.scheme == "http" else http.client.HTTPSConnection
        conn = conn_cls(parsed.hostname, parsed.port, timeout=timeout)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read()
        return resp.status


# =========================
# Локальный stub-сервер (если нет внешнего сервинга)
# =========================
class _StubHandler(BaseHTTPRequestHandler):
    # Путь к модели передаём через server.model_path
    server_version = "NeuroForgeStub/1.0"

    def log_message(self, fmt, *args):
        # Глушим лишние логи в тестах
        return

    def do_GET(self):
        if self.path.startswith("/health"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path.startswith("/predict"):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length > 0 else b"{}"
                payload = json.loads(raw.decode("utf-8"))
                inputs = payload.get("inputs", [])
                # Простая "инференция": y = sum(inputs) * scale из артефакта
                model_path = getattr(self.server, "model_path", None)  # type: ignore[attr-defined]
                if not model_path or not os.path.exists(model_path):
                    scale = 1.0
                    version = "0"
                else:
                    with open(model_path, "r", encoding="utf-8") as fp:
                        md = json.load(fp)
                    scale = float(md.get("scale", 1.0))
                    version = str(md.get("version", "0"))
                try:
                    s = float(sum(float(x) for x in inputs)) * scale
                except Exception:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "invalid inputs"}).encode("utf-8"))
                    return
                resp = {"outputs": s, "model_version": version}
                data = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()


class _StubServer(threading.Thread):
    def __init__(self, host: str, port: int, model_path: str):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.model_path = model_path
        self.httpd: Optional[HTTPServer] = None

    def run(self):
        self.httpd = HTTPServer((self.host, self.port), _StubHandler)
        # Пробросим путь к модели в инстанс сервера
        setattr(self.httpd, "model_path", self.model_path)  # type: ignore[attr-defined]
        self.httpd.serve_forever(poll_interval=0.25)

    def stop(self):
        if self.httpd:
            with contextlib.suppress(Exception):
                self.httpd.shutdown()
            with contextlib.suppress(Exception):
                self.httpd.server_close()


# =========================
# Фикстуры PyTest
# =========================
@pytest.fixture(scope="function")
def _tmpdir():
    with tempfile.TemporaryDirectory(prefix="neuroforge_e2e_") as d:
        yield pathlib.Path(d)

@pytest.fixture(scope="function")
def _model_artifact_paths(_tmpdir):
    model_dir = _tmpdir / "model"
    export_dir = _tmpdir / "export"
    model_dir.mkdir(parents=True, exist_ok=True)
    export_dir.mkdir(parents=True, exist_ok=True)
    return model_dir, export_dir

@pytest.fixture(scope="function")
def _stub_server(_model_artifact_paths):
    # Создаём начальную «модель»
    model_dir, _ = _model_artifact_paths
    model_meta = model_dir / "model.json"
    model_meta.write_text(json.dumps({"scale": 1.0, "version": 1}), encoding="utf-8")
    port = _find_free_port()
    server = _StubServer("127.0.0.1", port, str(model_meta))
    try:
        server.start()
        # Подождать запуска
        health_url = f"http://127.0.0.1:{port}/health"
        for _ in _sleep_backoff(5.0):
            if _http_get(health_url, timeout=1.5) == 200:
                break
        yield server, port, model_meta
    finally:
        server.stop()


# =========================
# Основной E2E тест
# =========================
@pytest.mark.e2e
def test_train_to_serve_e2e(_tmpdir, _model_artifact_paths, _stub_server):
    """
    Запускает E2E сценарий:
    1) TRAIN: обучает модель (реальной командой или фиктивно).
    2) EXPORT: экспортирует модель (реальной командой или копированием).
    3) SERVE: поднимает сервис (реальной командой или локальным stub-ом).
    4) HEALTH: проверяет здоровье.
    5) PREDICT: выполняет несколько запросов, оценивает P95 и контракт ответа.
    6) RETRAIN: меняет артефакт (scale/version), убеждается в дрейфе предсказаний.
    """
    model_dir, export_dir = _model_artifact_paths
    model_meta = model_dir / "model.json"
    export_meta = export_dir / "model.json"

    # -------- TRAIN --------
    if ENV["TRAIN_CMD"]:
        cmd = _render_cmd(ENV["TRAIN_CMD"], model=str(model_meta))
        rc, out = _run_cmd(cmd, timeout=300)
        assert rc == 0, f"TRAIN failed (rc={rc}):\n{out}"
        assert model_meta.exists(), "TRAIN: model artifact missing"
    else:
        # Локальное «обучение»
        model_meta.write_text(json.dumps({"scale": 1.5, "version": 1}), encoding="utf-8")

    # -------- EXPORT --------
    if ENV["EXPORT_CMD"]:
        cmd = _render_cmd(ENV["EXPORT_CMD"], model=str(model_meta), export=str(export_meta))
        rc, out = _run_cmd(cmd, timeout=180)
        assert rc == 0, f"EXPORT failed (rc={rc}):\n{out}"
        assert export_meta.exists(), "EXPORT: exported artifact missing"
    else:
        # Простое копирование метаданных
        export_meta.write_text(model_meta.read_text(encoding="utf-8"), encoding="utf-8")

    # -------- SERVE --------
    server_proc = None
    base_url = ""
    predict_url = ""
    health_url = ""

    if ENV["SERVE_CMD"] and ENV["PREDICT_URL"] and ENV["HEALTH_URL"]:
        # Внешний сервинг (мы лишь ждём его готовности)
        base_url = ""
        predict_url = ENV["PREDICT_URL"]
        health_url = ENV["HEALTH_URL"]
        # Если надо — можем стартовать процесс сервера командой
        if "{export}" in ENV["SERVE_CMD"] or "{port}" in ENV["SERVE_CMD"]:
            # Порт может быть не нужен, если ваш сервер слушает фиксированный порт
            port = _find_free_port()
            cmd = _render_cmd(ENV["SERVE_CMD"], export=str(export_dir), port=str(port))
            server_proc = subprocess.Popen(cmd, cwd=(ENV["SERVE_WORKDIR"] or None), shell=True)
            # Если ваша команда сама формирует URL, задайте HEALTH_URL/PREDICT_URL через ENV
        # Ожидание готовности
        ready = False
        for _ in _sleep_backoff(ENV["STARTUP_TIMEOUT_S"], step_s=0.5):
            try:
                if _http_get(health_url, timeout=2.0) == 200:
                    ready = True
                    break
            except Exception:
                pass
        assert ready, f"SERVE: healthcheck failed within {ENV['STARTUP_TIMEOUT_S']}s"
    else:
        # Локальный stub
        server, port, stub_model = _stub_server
        base_url = f"http://127.0.0.1:{port}"
        health_url = f"{base_url}/health"
        predict_url = f"{base_url}/predict"
        # Перекладываем экспорт в «рабочую» модель сервера
        stub_model.write_text(export_meta.read_text(encoding="utf-8"), encoding="utf-8")

    # -------- HEALTH --------
    status = _http_get(health_url, timeout=3.0)
    assert status == 200, f"HEALTH not ready: {status}"

    # -------- PREDICT (до переобучения) --------
    inputs = [1, 2, 3, 4.5]
    latencies_ms = []
    outputs_first = None
    version_first = None

    for _ in range(max(ENV["PREDICT_REPEATS"], 3)):
        code, resp, dt = _http_post_json(predict_url, {"inputs": inputs}, timeout=10.0)
        latencies_ms.append(int(dt * 1000))
        assert code == 200, f"PREDICT failed: {code} {resp}"
        assert "outputs" in resp and "model_version" in resp, f"Invalid response schema: {resp}"
        # Сохраним эталон
        if outputs_first is None:
            outputs_first = resp["outputs"]
            version_first = str(resp["model_version"])
        else:
            # Идемпотентность: одинаковый ввод -> одинаковый вывод
            assert resp["outputs"] == outputs_first

    # SLA по p95
    latencies_ms.sort()
    p95 = latencies_ms[int(len(latencies_ms) * 0.95) - 1]
    assert p95 <= ENV["SLA_P95_MS"], f"SLA violation: p95={p95}ms > {ENV['SLA_P95_MS']}ms"

    # -------- RETRAIN --------
    # Обновляем «артефакт» так, чтобы менялся результат предсказания
    if ENV["TRAIN_CMD"]:
        # Если у вас настоящий трейн — вызовите с иными гиперами/версией.
        # Здесь мы просто перепакуем export с новой версией через EXPORT_CMD (если оно есть),
        # иначе — прямой записью.
        pass

    new_scale = round(random.uniform(1.8, 2.5), 3)
    new_version = (int(version_first or "1") + 1) if (version_first or "").isdigit() else 2
    updated = {"scale": new_scale, "version": new_version}
    export_meta.write_text(json.dumps(updated), encoding="utf-8")

    # Для внешнего сервинга возможны разные механики reload; в нашем stub сервер читает файл на каждый запрос.
    if not (ENV["SERVE_CMD"] and ENV["PREDICT_URL"] and ENV["HEALTH_URL"]):
        # Скопируем обновление в stub «рабочий» файл
        _stub_server[2].write_text(export_meta.read_text(encoding="utf-8"), encoding="utf-8")

    # Немного подождать, если прод-сервер делает hot-reload асинхронно
    time.sleep(0.5)

    code, resp2, _ = _http_post_json(predict_url, {"inputs": inputs}, timeout=10.0)
    assert code == 200, f"PREDICT after retrain failed: {code} {resp2}"
    assert resp2.get("outputs") != outputs_first or str(resp2.get("model_version")) != str(version_first), \
        f"No drift detected after retrain: outputs {resp2.get('outputs')} vs {outputs_first}, " \
        f"version {resp2.get('model_version')} vs {version_first}"

    # -------- TEARDOWN --------
    if server_proc:
        with contextlib.suppress(Exception):
            server_proc.terminate()
        try:
            server_proc.wait(timeout=10)
        except Exception:
            with contextlib.suppress(Exception):
                server_proc.kill()


# =========================
# Доп. тест: схема ответа
# =========================
def test_predict_contract_schema(_stub_server):
    """
    Минимальная проверка контракта ответа /predict
    """
    _, port, _ = _stub_server
    url = f"http://127.0.0.1:{port}/predict"
    code, resp, _ = _http_post_json(url, {"inputs": [0, 1, 2.0]})
    assert code == 200
    assert isinstance(resp.get("outputs"), (int, float)), f"outputs should be number, got {type(resp.get('outputs'))}"
    assert "model_version" in resp, "model_version is required"
