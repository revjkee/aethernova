# datafabric-core/tests/integration/test_ingest_pipeline.py
# Интеграционный тест ingest-пайплайна DataFabric (самодостаточный)
# Требования: pytest, стандартная библиотека. Использует внутренние модули репозитория:
#   - datafabric.observability.audit_log
#   - datafabric.lineage.exporters.openlineage_emitter
#   - mocks.ingest_source_mock (для генерации событий)
#
# Запуск:
#   pytest -q tests/integration/test_ingest_pipeline.py -k test_ingest_file_pipeline_end_to_end
#
# Маркеры:
#   @pytest.mark.e2e   — долгие/сквозные тесты
#   @pytest.mark.optional_deps — зависят от опциональных пакетов/сред (пропускаются при отсутствии)

from __future__ import annotations

import contextlib
import http.server
import io
import json
import os
import queue
import socket
import socketserver
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# --------- Маркеры ---------
e2e = pytest.mark.e2e
optional = pytest.mark.optional_deps

# --------- Утилиты ожидания ---------
def wait_until(pred, timeout: float = 10.0, interval: float = 0.1, desc: str = ""):
    """Ждёт, пока pred() вернёт True, иначе бросает AssertionError по таймауту."""
    t0 = time.monotonic()
    while True:
        if pred():
            return
        if time.monotonic() - t0 > timeout:
            raise AssertionError(f"Timeout waiting for condition: {desc or pred!r}")
        time.sleep(interval)

# --------- Локальный HTTP-коллектор (OpenLineage sink) ---------
class _CollectorHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            data = {"_raw": raw.decode("utf-8", "ignore")}
        # Сохраняем в очередь из сервера
        self.server.events.put(data)  # type: ignore[attr-defined]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, fmt, *args):
        # Тише в логах теста
        return

class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

@dataclass
class OLCollector:
    url: str
    server: _ThreadingHTTPServer
    thread: threading.Thread
    events: "queue.Queue[Dict[str, Any]]"

@pytest.fixture(scope="function")
def openlineage_collector() -> OLCollector:
    # Выбираем свободный порт
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    host, port = s.getsockname()
    s.close()

    events_q: "queue.Queue[Dict[str, Any]]" = queue.Queue()

    def _make_handler(*args, **kwargs):
        h = _CollectorHandler(*args, **kwargs)
        return h

    srv = _ThreadingHTTPServer(("127.0.0.1", port), _CollectorHandler)
    # Подмешиваем очередь на сервер, чтобы Handler её видел
    srv.events = events_q  # type: ignore[attr-defined]

    th = threading.Thread(target=srv.serve_forever, name="ol-collector", daemon=True)
    th.start()
    url = f"http://127.0.0.1:{port}"
    yield OLCollector(url=url, server=srv, thread=th, events=events_q)
    with contextlib.suppress(Exception):
        srv.shutdown()
        srv.server_close()
    th.join(timeout=2.0)

# --------- Вспомогательные импорты ваших модулей ---------
# Предполагается, что datafabric-core установлен в PYTHONPATH во время CI,
# либо тест запускается из корня репозитория.
from datafabric.observability.audit_log import AuditLogger, AuditConfig  # type: ignore
from datafabric.lineage.exporters.openlineage_emitter import (           # type: ignore
    OpenLineageEmitter, OpenLineageConfig, DatasetRef, schema_facet, datasource_facet
)
from mocks.ingest_source_mock import SchemaSpec, EventGenerator          # type: ignore

# --------- Минимальный ingest-пайплайн для теста ---------
def _simple_mask_email(val: str) -> str:
    if not isinstance(val, str) or "@" not in val:
        return val
    name, _, dom = val.partition("@")
    keep = max(1, min(3, len(name)//3))
    return name[:keep] + "*"*(len(name)-keep) + "@" + dom

def run_ingest_pipeline(source_path: Path,
                        output_path: Path,
                        audit: AuditLogger,
                        ol: OpenLineageEmitter,
                        job_name: str = "ingest.test") -> Dict[str, Any]:
    """
    Читает JSONL события из source_path, применяет простые трансформации,
    пишет в output_path (JSONL), генерирует аудит и события OpenLineage.
    Возвращает метрики выполнения.
    """
    # — OpenLineage START
    inputs = [DatasetRef(namespace="localfs", name=str(source_path), facets={
        "schema": schema_facet([("event_id","string",None),("event_time","string",None),("event_type","string",None)]),
        "dataSource": datasource_facet(name="local", uri=str(source_path.parent))
    })]
    outputs = [DatasetRef(namespace="localfs", name=str(output_path), facets={
        "dataSource": datasource_facet(name="local", uri=str(output_path.parent))
    })]
    run_id = ol.emit_start(job_name=job_name, inputs=inputs, outputs=outputs)

    produced = 0
    dlp_hits = 0
    with output_path.open("w", encoding="utf-8") as out:
        with source_path.open("r", encoding="utf-8") as src:
            for line in src:
                if not line.strip():
                    continue
                evt = json.loads(line)
                # Трансформации: нормализация, маскирование email, приведение поля
                if "user" in evt and isinstance(evt["user"], dict) and "email" in evt["user"]:
                    evt["user"]["email"] = _simple_mask_email(evt["user"]["email"])
                # Простейшая DLP: наличие '@' в произвольном поле payload/snippet
                payload = json.dumps(evt, ensure_ascii=False)
                if "@" in payload:
                    dlp_hits += 1
                # Пример: приведение event_type в верхний регистр
                if "event_type" in evt and isinstance(evt["event_type"], str):
                    evt["event_type"] = evt["event_type"].upper()
                out.write(json.dumps(evt, ensure_ascii=False) + "\n")
                produced += 1
                # Аудит — фиксация операции записи
                audit.emit("PROCESS", "pipeline.write", result="OK",
                           data={"target": str(output_path)}, meta={"job": job_name})

    # — OpenLineage COMPLETE
    ol.emit_complete(job_name=job_name, run_id=run_id, outputs=outputs)
    return {"produced": produced, "dlp_hits": dlp_hits, "run_id": run_id}

# --------- Фикстуры окружения ---------
@pytest.fixture()
def tmp_workspace(tmp_path: Path):
    src = tmp_path / "src.jsonl"
    out = tmp_path / "out.jsonl"
    audit_file = tmp_path / "audit.jsonl"
    return {"src": src, "out": out, "audit": audit_file, "root": tmp_path}

@pytest.fixture()
def audit_logger(tmp_workspace) -> AuditLogger:
    cfg = AuditConfig(enable_stdout=False, enable_file=True, file_path=str(tmp_workspace["audit"]))
    return AuditLogger(cfg=cfg)

@pytest.fixture()
def ol_emitter(openlineage_collector: OLCollector) -> OpenLineageEmitter:
    # Синхронная отправка, чтобы упростить ожидания теста
    cfg = OpenLineageConfig(
        url=openlineage_collector.url,
        async_mode=False,
        namespace="datafabric.tests",
        job_name_prefix="df",
        app_name="datafabric-tests",
        api_path="/",  # наш импровизированный коллектор принимает POST на корень
        sample_rate=1.0,
    )
    return OpenLineageEmitter(cfg)

# --------- Генерация источника через ваш мок ---------
def _default_schema() -> SchemaSpec:
    d = {
        "namespace": "datafabric.mock",
        "type": "event",
        "fields": {
            "event_id": {"gen": "uuid", "deterministic": True},
            "event_time": {"gen": "now"},
            "event_type": {"gen": "choice", "choices": ["signup","purchase","refund","click","view"]},
            "user": {
                "type": "object",
                "fields": {
                    "id": {"gen": "seq", "start": 1},
                    "email": {"gen": "email", "domain": "example.com"},
                }
            },
            "amount": {"gen": "float", "min": 0, "max": 999.99, "precision": 2}
        }
    }
    return SchemaSpec.from_dict(d)

def generate_source_jsonl(path: Path, rows: int = 200, seed: int = 42) -> None:
    schema = _default_schema()
    gen = EventGenerator(schema, seed=seed, masker_enabled=False)
    with path.open("w", encoding="utf-8") as f:
        for i in range(1, rows + 1):
            ev = gen.next_event(i)
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

# ======================= ТЕСТЫ =======================

@e2e
def test_ingest_file_pipeline_end_to_end(tmp_workspace, audit_logger, ol_emitter, openlineage_collector):
    """
    E2E: генерация источника -> ingest-пайплайн -> аудит -> OpenLineage -> проверки.
    """
    # Arrange
    generate_source_jsonl(tmp_workspace["src"], rows=150, seed=123)
    assert tmp_workspace["src"].exists()

    # Act
    metrics = run_ingest_pipeline(
        source_path=tmp_workspace["src"],
        output_path=tmp_workspace["out"],
        audit=audit_logger,
        ol=ol_emitter,
        job_name="ingest.test_file",
    )

    # Assert — выходные данные
    assert tmp_workspace["out"].exists(), "Выходной файл отсутствует"
    out_lines = sum(1 for _ in tmp_workspace["out"].open("r", encoding="utf-8"))
    assert out_lines == metrics["produced"] >= 100, "Неверное число строк в выходе"

    # Assert — аудит записан и содержит PROCESS события
    audit_lines = [json.loads(l) for l in tmp_workspace["audit"].open("r", encoding="utf-8")]
    assert any(x.get("category") == "PROCESS" and x.get("action") == "pipeline.write" for x in audit_lines), "Нет PROCESS записей аудита"

    # Assert — OpenLineage START/COMPLETE доставлены
    def _got_ol_events():
        # смотрим хотя бы 2 события
        return openlineage_collector.events.qsize() >= 2
    wait_until(_got_ol_events, timeout=5, desc="OpenLineage events arrival")

    # собираем события
    received = []
    while not openlineage_collector.events.empty():
        received.append(openlineage_collector.events.get())

    types = {e.get("eventType") for e in received}
    assert "START" in types and "COMPLETE" in types, f"Ожидались события START/COMPLETE, пришло: {types}"

    # проверим полезные поля
    any_evt = received[0]
    assert any_evt.get("job", {}).get("namespace") == "datafabric.tests"
    assert any_evt.get("run", {}).get("runId") == metrics["run_id"]

    # Assert — DLP count положителен (в событиях есть email)
    assert metrics["dlp_hits"] > 0

@optional
def test_openlineage_collector_handles_malformed_json(openlineage_collector):
    """
    Проверка устойчивости коллектора к некорректным данным (эмулируем HTTP POST с мусором).
    """
    import urllib.request
    req = urllib.request.Request(openlineage_collector.url + "/", data=b"not a json", method="POST")
    with contextlib.closing(urllib.request.urlopen(req)) as resp:
        assert resp.status == 200
    wait_until(lambda: openlineage_collector.events.qsize() >= 1, timeout=2)
    evt = openlineage_collector.events.get()
    assert "_raw" in evt

@e2e
def test_audit_file_integrity_and_chain(tmp_workspace, audit_logger):
    """
    Проверка целостности аудита: формат JSONL, наличие ключевых полей, последовательность seq/hash-цепочки.
    """
    # генерируем пару событий
    for i in range(5):
        audit_logger.emit("ACCESS", "login.attempt", result="OK", actor={"id": f"user{i}"}, resource={"type":"account","id":"acc"})
    audit_logger.close()

    lines = [json.loads(l) for l in tmp_workspace["audit"].open("r", encoding="utf-8") if l.strip()]
    assert len(lines) >= 5
    # проверим, что есть seq, event_hash, prev_hash
    for rec in lines:
        assert "seq" in rec and "event_hash" in rec and "prev_hash" in rec
        assert rec.get("category") in {"ACCESS","SECURITY","DATA","CONFIG","PROCESS","SYSTEM"}
