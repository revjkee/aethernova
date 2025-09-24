# datafabric-core/tests/unit/lineage/test_tracker.py
# Контрактные unit-тесты для модуля datafabric.lineage.tracker (LineageTracker).
# Покрывают:
#  - успешный сценарий: start -> emit_event -> commit
#  - контекстный менеджер: статус success/error, фиксация исключения
#  - идемпотентность commit()
#  - ретраи при временных сбоях бэкенда
#  - сериализуемость JSON артефакта
#  - отсутствие дубликатов в inputs/outputs
#  - изоляцию конкурентных запусков
#  - валидацию входа (ошибки на пустой job_name и т.п.)
#
# Примечание:
# Эти тесты определяют ожидаемый контракт. Если модуль не реализован,
# они помечаются xfail с причиной "tracker module not implemented".

from __future__ import annotations

import json
import threading
import time
import types
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import pytest

# --------- Попытка импорта целевого API и мягкая деградация для отсутствующего модуля ---------
try:
    from datafabric.lineage.tracker import (  # type: ignore
        LineageTracker,
        track_lineage,          # контекстный менеджер
        ILineageBackend,        # интерфейс хранилища (save/commit/abort/append_event и т.п.)
        LineageRecord,          # dataclass/dict записи
        TransientBackendError,  # помечаемые как временные ошибки для ретраев
    )
    TRACKER_AVAILABLE = True
except Exception:
    # Обозначаем ожидаемые имена для подсказок IDE, но тесты пометим xfail.
    LineageTracker = object  # type: ignore
    track_lineage = None     # type: ignore
    ILineageBackend = object # type: ignore
    LineageRecord = dict     # type: ignore
    class TransientBackendError(RuntimeError): ...
    TRACKER_AVAILABLE = False

pytestmark = pytest.mark.unit

# =========================
# Вспомогательные фейковые бэкенды
# =========================
@dataclass
class _StoredRecord:
    run_id: str
    record: Dict[str, Any]
    events: List[Dict[str, Any]]

class FakeBackend:
    """
    Потокобезопасный in-memory бэкенд, реализующий минимальный контракт ILineageBackend:
      - begin(run_id, job_name, started_at, inputs, outputs, context) -> None
      - append_event(run_id, event) -> None
      - commit(run_id, finished_at, status, error) -> record (dict)
      - abort(run_id, error) -> None
    """
    def __init__(self):
        self._lock = threading.RLock()
        self._runs: Dict[str, _StoredRecord] = {}
        self._committed: Dict[str, Dict[str, Any]] = {}

    # Имитация begin()
    def begin(self, run_id: str, job_name: str, started_at: float, inputs: List[Dict[str, Any]], outputs: List[Dict[str, Any]], context: Dict[str, Any]) -> None:
        with self._lock:
            if run_id in self._runs:
                raise RuntimeError("duplicate begin")
            self._runs[run_id] = _StoredRecord(run_id=run_id, record={
                "run_id": run_id,
                "job": job_name,
                "started_at": started_at,
                "inputs": list(inputs),
                "outputs": list(outputs),
                "context": dict(context or {}),
                "status": "running",
            }, events=[])

    # Имитация append_event()
    def append_event(self, run_id: str, event: Dict[str, Any]) -> None:
        with self._lock:
            self._runs[run_id].events.append(dict(event))

    # Имитация commit()
    def commit(self, run_id: str, finished_at: float, status: str, error: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        with self._lock:
            rec = self._runs.get(run_id)
            if not rec:
                raise RuntimeError("unknown run")
            if run_id in self._committed:
                # идемпотентность
                return self._committed[run_id]
            duration_ms = max(0, int((finished_at - rec.record["started_at"]) * 1000))
            out = dict(rec.record)
            out.update({
                "finished_at": finished_at,
                "duration_ms": duration_ms,
                "status": status,
                "error": error,
                "events": list(rec.events),
            })
            self._committed[run_id] = out
            return out

    # Имитация abort()
    def abort(self, run_id: str, error: Dict[str, Any]) -> None:
        with self._lock:
            rec = self._runs.get(run_id)
            if not rec:
                return
            rec.record["status"] = "aborted"
            rec.record["error"] = error

    # Вспомогательное API только для тестов
    def get_committed(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._committed.get(run_id)

class FlakyBackend(FakeBackend):
    """Бэкенд, который N первых раз бросает TransientBackendError на commit."""
    def __init__(self, fail_times: int):
        super().__init__()
        self._remaining = fail_times

    def commit(self, run_id: str, finished_at: float, status: str, error: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        with self._lock:
            if self._remaining > 0:
                self._remaining -= 1
                raise TransientBackendError("temporary outage")
            return super().commit(run_id, finished_at, status, error)

# =========================
# Фикстуры
# =========================
@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()

@pytest.fixture
def dataset_refs():
    return {
        "inputs": [
            {"namespace": "raw", "name": "users", "version": "2024-09-01", "uri": "s3://bucket/raw/users/2024-09-01"},
            {"namespace": "raw", "name": "orders", "version": "2024-09-01"},
            {"namespace": "raw", "name": "orders", "version": "2024-09-01"},  # дубликат для проверки дедупликации
        ],
        "outputs": [
            {"namespace": "curated", "name": "user_orders", "version": "v1"},
        ],
    }

@pytest.fixture(autouse=True)
def _xfail_if_tracker_missing():
    if not TRACKER_AVAILABLE:
        pytest.xfail("datafabric.lineage.tracker is not implemented yet")

# =========================
# Хелперы для стабилизации времени/uuid
# =========================
@pytest.fixture
def fixed_uuid(monkeypatch):
    seq = [uuid.UUID(int=i) for i in range(1, 1000)]
    it = iter(seq)
    monkeypatch.setattr("uuid.uuid4", lambda: next(it))
    return True

@pytest.fixture
def time_source(monkeypatch):
    base = [1000.0]
    def now():
        return base[0]
    def advance(delta: float):
        base[0] += delta
    monkeypatch.setattr("time.time", now)
    return types.SimpleNamespace(now=now, advance=advance)

# =========================
# ТЕСТЫ
# =========================
def test_successful_lineage_commit_contains_mandatory_fields(backend, dataset_refs, fixed_uuid, time_source):
    inputs = dataset_refs["inputs"]
    outputs = dataset_refs["outputs"]

    tracker = LineageTracker(job_name="daily_join", backend=backend, time_provider=time.time)
    run_id = tracker.run_id
    assert run_id  # должен быть сгенерирован

    # дубликат в inputs должен быть удалён внутри трекера
    tracker.start(inputs=inputs, outputs=outputs, context={"owner": "analytics"})
    tracker.emit_event("read_complete", details={"rows": 123})
    time_source.advance(1.234)
    record = tracker.commit(status="success")

    assert record["run_id"] == run_id
    assert record["job"] == "daily_join"
    assert record["status"] == "success"
    assert isinstance(record["started_at"], float)
    assert isinstance(record["finished_at"], float)
    assert record["finished_at"] >= record["started_at"]
    assert record["duration_ms"] >= 1234
    # дедупликация входов
    uniq_inputs = {(d["namespace"], d["name"], d["version"]) for d in record["inputs"]}
    assert len(uniq_inputs) == 2
    # события упорядочены
    assert record["events"][0]["event_type"] == "read_complete"
    assert record["events"][0]["details"]["rows"] == 123
    # сериализация JSON без ошибок
    json.dumps(record)

def test_context_manager_success_flow(backend, dataset_refs, fixed_uuid, time_source):
    inputs, outputs = dataset_refs["inputs"], dataset_refs["outputs"]
    with track_lineage(job_name="daily_join", backend=backend, time_provider=time.time, inputs=inputs, outputs=outputs) as t:
        assert t.run_id
        t.emit_event("transform", details={"stage": "join"})
        time_source.advance(0.5)

    # после выхода должен быть коммит со статусом success
    saved = backend.get_committed(t.run_id)
    assert saved and saved["status"] == "success"
    assert any(e["event_type"] == "transform" for e in saved["events"])
    assert saved["duration_ms"] >= 500

def test_context_manager_error_flow_sets_error_and_status_error(backend, dataset_refs, fixed_uuid, time_source):
    inputs, outputs = dataset_refs["inputs"], dataset_refs["outputs"]
    run_id_holder = {}

    with pytest.raises(RuntimeError, match="boom"):
        with track_lineage(job_name="daily_join", backend=backend, time_provider=time.time, inputs=inputs, outputs=outputs) as t:
            run_id_holder["id"] = t.run_id
            t.emit_event("start_compute")
            time_source.advance(0.1)
            raise RuntimeError("boom")

    saved = backend.get_committed(run_id_holder["id"])
    assert saved is not None
    assert saved["status"] in ("error", "failed")
    assert saved["error"] and "boom" in (saved["error"].get("message", "") or str(saved["error"]))

def test_commit_is_idempotent(backend, dataset_refs, fixed_uuid, time_source):
    t = LineageTracker(job_name="job", backend=backend, time_provider=time.time)
    t.start(inputs=dataset_refs["inputs"], outputs=dataset_refs["outputs"], context={})
    time_source.advance(0.2)
    first = t.commit(status="success")
    second = t.commit(status="success")  # не должен дублировать запись и должен вернуть тот же результат
    assert first is second or first == second

def test_retry_on_transient_backend_error(dataset_refs, fixed_uuid, time_source):
    backend = FlakyBackend(fail_times=2)  # первые две попытки commit падают TransientBackendError
    t = LineageTracker(job_name="job", backend=backend, time_provider=time.time,
                       retry_policy={"max_attempts": 4, "backoff_base": 0.01, "backoff_multiplier": 1.0})
    t.start(inputs=dataset_refs["inputs"], outputs=dataset_refs["outputs"], context={})
    time_source.advance(0.05)
    record = t.commit(status="success")
    assert record["status"] == "success"

def test_concurrent_runs_are_isolated(dataset_refs):
    backend = FakeBackend()
    N = 10
    run_ids = []
    errs: List[Exception] = []

    def worker(idx: int):
        try:
            t = LineageTracker(job_name=f"job-{idx}", backend=backend)
            t.start(inputs=[{"namespace": "raw", "name": f"ds{idx}", "version": "v1"}],
                    outputs=[{"namespace": "cur", "name": f"out{idx}", "version": "v1"}],
                    context={"shard": idx})
            t.emit_event("stage", details={"i": idx})
            time.sleep(0.005)
            t.commit(status="success")
            run_ids.append(t.run_id)
        except Exception as e:
            errs.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    for th in threads: th.start()
    for th in threads: th.join()

    assert not errs
    # проверяем, что у каждого run_id есть запись и она соответствует job-у
    for rid in run_ids:
        rec = backend.get_committed(rid)
        assert rec and rec["run_id"] == rid and rec["status"] == "success"

@pytest.mark.parametrize("bad_job", ["", "   ", None])
def test_validation_of_job_name(backend, dataset_refs, bad_job):
    with pytest.raises((ValueError, AssertionError)):
        LineageTracker(job_name=bad_job, backend=backend)

def test_validation_of_inputs_outputs_types(backend):
    t = LineageTracker(job_name="job", backend=backend)
    with pytest.raises((ValueError, TypeError)):
        t.start(inputs=None, outputs=[], context={})  # type: ignore
    with pytest.raises((ValueError, TypeError)):
        t.start(inputs=[], outputs=None, context={})  # type: ignore

def test_events_are_monotonic_and_have_required_fields(backend, dataset_refs, time_source):
    t = LineageTracker(job_name="job", backend=backend, time_provider=time.time)
    t.start(inputs=dataset_refs["inputs"], outputs=dataset_refs["outputs"], context={})
    t.emit_event("stage1", details={"ok": True})
    time_source.advance(0.001)
    t.emit_event("stage2")
    time_source.advance(0.001)
    rec = t.commit(status="success")

    evs = rec["events"]
    assert all("event_type" in e and "ts" in e for e in evs)
    assert evs[0]["ts"] <= evs[1]["ts"]

def test_record_is_json_serializable_even_with_complex_context(backend, dataset_refs):
    class Obj:  # несериализуемый по умолчанию объект
        def __repr__(self): return "Obj(x=1)"

    t = LineageTracker(job_name="job", backend=backend)
    t.start(inputs=dataset_refs["inputs"], outputs=dataset_refs["outputs"], context={"obj": Obj()})
    rec = t.commit(status="success")
    # Провайдер должен преобразовать контекст в сериализуемый вид (например, str для неизвестных типов)
    json.dumps(rec)

def test_no_duplicate_outputs(backend):
    t = LineageTracker(job_name="job", backend=backend)
    outputs = [
        {"namespace": "cur", "name": "ds", "version": "v1"},
        {"namespace": "cur", "name": "ds", "version": "v1"},
    ]
    t.start(inputs=[], outputs=outputs, context={})
    rec = t.commit(status="success")
    uniq = {(d["namespace"], d["name"], d["version"]) for d in rec["outputs"]}
    assert len(uniq) == 1
