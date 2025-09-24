# path: datafabric/lineage/tracker.py
"""
Industrial Data Lineage Tracker for DataFabric

Features:
- Event model: Job, Run, Dataset, IO (read, write), Facets, Metrics, Tags
- Sync and Async API
- Pluggable storage backends: InMemory, JSONL (append only), SQLite (transactional)
- OpenLineage-style payload exports (subset)
- Function decorator for auto-instrumentation of Python tasks
- Redaction guard for secrets and PII-like keys
- Deterministic IDs and code fingerprinting
- Graph export: adjacency JSON and Graphviz DOT
- Query helpers: lineage for dataset, job, run
- Thread-safe with RLock, process-safe for JSONL via file locks
- Minimal dependencies: stdlib only

Public entrypoints:
- LineageTracker
- lineage_task decorator
- Storage backends: InMemoryStore, JSONLStore, SQLiteStore
"""

from __future__ import annotations

import atexit
import contextlib
import dataclasses
import datetime as dt
import functools
import hashlib
import inspect
import io
import json
import os
import sqlite3
import sys
import threading
import time
import traceback
import types
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

__all__ = [
    "EventType",
    "DatasetRef",
    "JobRef",
    "RunRef",
    "Facet",
    "Metric",
    "LineageEvent",
    "LineageStore",
    "InMemoryStore",
    "JSONLStore",
    "SQLiteStore",
    "LineageTracker",
    "lineage_task",
]

# ---------------------------
# Model
# ---------------------------

class EventType(str):
    START = "START"
    COMPLETE = "COMPLETE"
    FAIL = "FAIL"
    ABORT = "ABORT"
    READ = "READ"
    WRITE = "WRITE"
    MARK = "MARK"

@dataclass(frozen=True)
class DatasetRef:
    namespace: str
    name: str
    version: Optional[str] = None
    facets: Mapping[str, Any] = field(default_factory=dict)

    def id(self) -> str:
        v = self.version or ""
        return f"{self.namespace}:{self.name}:{v}"

@dataclass(frozen=True)
class JobRef:
    namespace: str
    name: str
    facets: Mapping[str, Any] = field(default_factory=dict)

    def id(self) -> str:
        return f"{self.namespace}:{self.name}"

@dataclass(frozen=True)
class RunRef:
    run_id: str
    parent_run_id: Optional[str] = None
    facets: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class Facet:
    name: str
    data: Mapping[str, Any]

@dataclass(frozen=True)
class Metric:
    name: str
    value: Union[int, float]
    unit: Optional[str] = None
    extras: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class LineageEvent:
    event_time: str
    event_type: str
    producer: str
    job: JobRef
    run: RunRef
    inputs: Sequence[DatasetRef] = field(default_factory=tuple)
    outputs: Sequence[DatasetRef] = field(default_factory=tuple)
    facets: Mapping[str, Any] = field(default_factory=dict)
    metrics: Sequence[Metric] = field(default_factory=tuple)
    tags: Sequence[str] = field(default_factory=tuple)
    error: Optional[str] = None

    def key(self) -> str:
        sig = f"{self.event_type}|{self.job.id()}|{self.run.run_id}|{self.event_time}"
        return hashlib.sha256(sig.encode("utf-8")).hexdigest()

# ---------------------------
# Redaction guard
# ---------------------------

_DEFAULT_REDACT_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "authorization",
    "auth",
    "key",
    "private_key",
    "conn_str",
    "connection_string",
}

def redact(obj: Any, keys: Optional[Iterable[str]] = None) -> Any:
    keys_lower = set(k.lower() for k in (keys or _DEFAULT_REDACT_KEYS))
    def _red(x: Any) -> Any:
        if isinstance(x, Mapping):
            out = {}
            for k, v in x.items():
                if str(k).lower() in keys_lower:
                    out[k] = "***"
                else:
                    out[k] = _red(v)
            return out
        if isinstance(x, (list, tuple)):
            return type(x)(_red(v) for v in x)
        return x
    return _red(obj)

# ---------------------------
# Storage interfaces
# ---------------------------

class LineageStore:
    def write(self, ev: LineageEvent) -> None:
        raise NotImplementedError

    def bulk_write(self, events: Sequence[LineageEvent]) -> None:
        for e in events:
            self.write(e)

    def read_all(self) -> Iterable[LineageEvent]:
        raise NotImplementedError

    def query_by_run(self, run_id: str) -> List[LineageEvent]:
        return [e for e in self.read_all() if e.run.run_id == run_id]

    def query_by_job(self, job_id: str) -> List[LineageEvent]:
        ns, name = job_id.split(":", 1)
        return [e for e in self.read_all() if e.job.namespace == ns and e.job.name == name]

    def query_by_dataset(self, dataset_id: str) -> List[LineageEvent]:
        ns, name, *rest = dataset_id.split(":")
        version = rest[0] if rest else None
        out = []
        for e in self.read_all():
            ins = [d for d in e.inputs if d.namespace == ns and d.name == name and (version is None or d.version == version)]
            outs = [d for d in e.outputs if d.namespace == ns and d.name == name and (version is None or d.version == version)]
            if ins or outs:
                out.append(e)
        return out

# In-memory store

class InMemoryStore(LineageStore):
    def __init__(self):
        self._buf: List[LineageEvent] = []
        self._lock = threading.RLock()

    def write(self, ev: LineageEvent) -> None:
        with self._lock:
            self._buf.append(ev)

    def read_all(self) -> Iterable[LineageEvent]:
        with self._lock:
            return list(self._buf)

# JSONL append-only store with simple file lock

class JSONLStore(LineageStore):
    def __init__(self, path: Union[str, Path]):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = self._path.with_suffix(self._path.suffix + ".lock")
        self._lock_file = None
        self._lock = threading.RLock()

    def _acquire_fs_lock(self):
        if os.name == "nt":
            # Best effort on Windows: create and hold open
            self._lock_file = open(self._lock_path, "a+", buffering=1)
            try:
                # no fcntl on Windows stdlib without msvcrt locking
                pass
            except Exception:
                pass
        else:
            import fcntl
            self._lock_file = open(self._lock_path, "a+", buffering=1)
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX)

    def _release_fs_lock(self):
        if self._lock_file:
            try:
                if os.name != "nt":
                    import fcntl
                    fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
            finally:
                try:
                    self._lock_file.close()
                except Exception:
                    pass
                self._lock_file = None

    def write(self, ev: LineageEvent) -> None:
        payload = _event_to_dict(ev)
        line = json.dumps(payload, ensure_ascii=False)
        with self._lock:
            self._acquire_fs_lock()
            try:
                with self._path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            finally:
                self._release_fs_lock()

    def read_all(self) -> Iterable[LineageEvent]:
        if not self._path.exists():
            return []
        out: List[LineageEvent] = []
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    out.append(_event_from_dict(d))
                except Exception:
                    continue
        return out

# SQLite store

class SQLiteStore(LineageStore):
    def __init__(self, path: Union[str, Path]):
        self._path = str(path)
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self._path) as con:
            con.execute("""
            create table if not exists events(
                k text primary key,
                ts text not null,
                type text not null,
                producer text not null,
                job_ns text not null,
                job_name text not null,
                run_id text not null,
                parent_run text,
                payload json not null
            )
            """)
            con.execute("create index if not exists idx_events_run on events(run_id)")
            con.execute("create index if not exists idx_events_job on events(job_ns, job_name)")
            con.commit()

    def write(self, ev: LineageEvent) -> None:
        d = _event_to_dict(ev)
        k = ev.key()
        with self._lock, sqlite3.connect(self._path) as con:
            con.execute(
                "insert or replace into events(k, ts, type, producer, job_ns, job_name, run_id, parent_run, payload) values(?,?,?,?,?,?,?,?,?)",
                (
                    k,
                    ev.event_time,
                    ev.event_type,
                    ev.producer,
                    ev.job.namespace,
                    ev.job.name,
                    ev.run.run_id,
                    ev.run.parent_run_id,
                    json.dumps(d, ensure_ascii=False),
                ),
            )
            con.commit()

    def read_all(self) -> Iterable[LineageEvent]:
        with sqlite3.connect(self._path) as con:
            cur = con.execute("select payload from events order by ts asc")
            return [_event_from_dict(json.loads(row[0])) for row in cur.fetchall()]

# ---------------------------
# Tracker
# ---------------------------

@dataclass
class TrackerConfig:
    producer: str = "datafabric-lineage"
    redact_keys: Sequence[str] = tuple(_DEFAULT_REDACT_KEYS)
    default_namespace: str = "datafabric"
    code_fingerprint: bool = True
    auto_flush_on_exit: bool = True

class LineageTracker:
    def __init__(self, store: LineageStore, config: Optional[TrackerConfig] = None):
        self._store = store
        self._cfg = config or TrackerConfig()
        self._lock = threading.RLock()
        self._buffer: List[LineageEvent] = []
        if self._cfg.auto_flush_on_exit:
            atexit.register(self.flush)

    # -------------- public sync api

    def start_run(
        self,
        job: JobRef,
        run: Optional[RunRef] = None,
        inputs: Sequence[DatasetRef] = (),
        outputs: Sequence[DatasetRef] = (),
        facets: Mapping[str, Any] = (),
        tags: Sequence[str] = (),
    ) -> RunRef:
        r = run or RunRef(run_id=_uuid())
        ev = self._event(EventType.START, job, r, inputs, outputs, facets, [], tags, None)
        self._write(ev)
        return r

    def complete_run(
        self,
        job: JobRef,
        run: RunRef,
        outputs: Sequence[DatasetRef] = (),
        metrics: Sequence[Metric] = (),
        facets: Mapping[str, Any] = (),
        tags: Sequence[str] = (),
    ) -> None:
        ev = self._event(EventType.COMPLETE, job, run, (), outputs, facets, metrics, tags, None)
        self._write(ev)

    def fail_run(
        self, job: JobRef, run: RunRef, error: Union[str, BaseException], facets: Mapping[str, Any] = (), tags: Sequence[str] = ()
    ) -> None:
        err = _format_exc(error)
        ev = self._event(EventType.FAIL, job, run, (), (), facets, (), tags, err)
        self._write(ev)

    def abort_run(self, job: JobRef, run: RunRef, reason: str = "aborted") -> None:
        ev = self._event(EventType.ABORT, job, run, (), (), {"abort": {"reason": reason}}, (), (), None)
        self._write(ev)

    def mark(
        self, job: JobRef, run: RunRef, message: str, facets: Mapping[str, Any] = (), tags: Sequence[str] = ()
    ) -> None:
        ev = self._event(EventType.MARK, job, run, (), (), {"mark": {"message": message, "time": _now()}}, (), tags, None)
        self._write(ev)

    def read(self, job: JobRef, run: RunRef, inputs: Sequence[DatasetRef], facets: Mapping[str, Any] = (), tags: Sequence[str] = ()):
        ev = self._event(EventType.READ, job, run, inputs, (), facets, (), tags, None)
        self._write(ev)

    def write(self, job: JobRef, run: RunRef, outputs: Sequence[DatasetRef], facets: Mapping[str, Any] = (), tags: Sequence[str] = ()):
        ev = self._event(EventType.WRITE, job, run, (), outputs, facets, (), tags, None)
        self._write(ev)

    def add_metric(self, job: JobRef, run: RunRef, metric: Metric, tags: Sequence[str] = ()):
        ev = self._event(EventType.MARK, job, run, (), (), {"metric": dataclasses.asdict(metric)}, (), tags, None)
        self._write(ev)

    def flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            buf = list(self._buffer)
            self._buffer.clear()
        self._store.bulk_write(buf)

    # -------------- async api

    async def start_run_async(self, *args, **kwargs) -> RunRef:
        return self.start_run(*args, **kwargs)

    async def complete_run_async(self, *args, **kwargs) -> None:
        self.complete_run(*args, **kwargs)

    async def fail_run_async(self, *args, **kwargs) -> None:
        self.fail_run(*args, **kwargs)

    async def abort_run_async(self, *args, **kwargs) -> None:
        self.abort_run(*args, **kwargs)

    async def read_async(self, *args, **kwargs) -> None:
        self.read(*args, **kwargs)

    async def write_async(self, *args, **kwargs) -> None:
        self.write(*args, **kwargs)

    async def add_metric_async(self, *args, **kwargs) -> None:
        self.add_metric(*args, **kwargs)

    async def flush_async(self) -> None:
        self.flush()

    # -------------- export and queries

    def export_openlineage(self, e: LineageEvent) -> Dict[str, Any]:
        return _event_to_openlineage(e)

    def export_graph_adjacency(self, events: Optional[Iterable[LineageEvent]] = None) -> Dict[str, List[str]]:
        evs = events if events is not None else self._store.read_all()
        graph: Dict[str, List[str]] = {}
        for e in evs:
            for inp in e.inputs:
                for out in e.outputs:
                    graph.setdefault(inp.id(), []).append(out.id())
        # deduplicate adjacency lists
        for k, v in list(graph.items()):
            graph[k] = sorted(set(v))
        return graph

    def export_graph_dot(self, events: Optional[Iterable[LineageEvent]] = None) -> str:
        graph = self.export_graph_adjacency(events)
        buf = io.StringIO()
        buf.write("digraph lineage {\n")
        buf.write('  rankdir=LR;\n  node [shape=box];\n')
        for src, outs in graph.items():
            safe_src = _dot_id(src)
            buf.write(f'  "{safe_src}";\n')
            for dst in outs:
                safe_dst = _dot_id(dst)
                buf.write(f'  "{safe_src}" -> "{safe_dst}";\n')
        buf.write("}\n")
        return buf.getvalue()

    def lineage_for_dataset(self, dataset_id: str) -> List[LineageEvent]:
        return self._store.query_by_dataset(dataset_id)

    def lineage_for_run(self, run_id: str) -> List[LineageEvent]:
        return self._store.query_by_run(run_id)

    def lineage_for_job(self, job_id: str) -> List[LineageEvent]:
        return self._store.query_by_job(job_id)

    # -------------- internals

    def _event(
        self,
        et: str,
        job: JobRef,
        run: RunRef,
        inputs: Sequence[DatasetRef],
        outputs: Sequence[DatasetRef],
        facets: Mapping[str, Any],
        metrics: Sequence[Metric],
        tags: Sequence[str],
        error: Optional[str],
    ) -> LineageEvent:
        payload_facets: Dict[str, Any] = dict(facets or {})
        payload_facets["datafabric"] = {
            "producer": self._cfg.producer,
            "ts_unix": time.time(),
        }
        if self._cfg.code_fingerprint:
            payload_facets["codeFingerprint"] = _code_fingerprint(2)

        ev = LineageEvent(
            event_time=_now(),
            event_type=et,
            producer=self._cfg.producer,
            job=job,
            run=run,
            inputs=tuple(_redact_ds(inputs, self._cfg)),
            outputs=tuple(_redact_ds(outputs, self._cfg)),
            facets=redact(payload_facets, self._cfg.redact_keys),
            metrics=tuple(metrics),
            tags=tuple(tags),
            error=error,
        )
        return ev

    def _write(self, ev: LineageEvent) -> None:
        with self._lock:
            self._buffer.append(ev)
            # Heuristic flush on terminal events
            if ev.event_type in (EventType.COMPLETE, EventType.FAIL, EventType.ABORT) or len(self._buffer) >= 128:
                buf = list(self._buffer)
                self._buffer.clear()
                self._store.bulk_write(buf)

# ---------------------------
# Decorator for tasks
# ---------------------------

def lineage_task(
    tracker: LineageTracker,
    job_namespace: str,
    job_name: Optional[str] = None,
    input_datasets: Optional[Sequence[DatasetRef]] = None,
    output_datasets: Optional[Sequence[DatasetRef]] = None,
    tags: Sequence[str] = (),
):
    """
    Decorate a function to emit START, READ, WRITE, COMPLETE or FAIL events automatically.

    Usage:
        @lineage_task(tracker, "etl", "daily_orders", [DatasetRef(...)] , [DatasetRef(...)] )
        def my_task(...): ...
    """
    def decorate(fn: Callable[..., Any]):
        jname = job_name or fn.__name__
        job = JobRef(job_namespace, jname)

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            run = RunRef(run_id=_uuid())
            tracker.start_run(job, run, inputs=input_datasets or (), outputs=(), facets={"function": {"name": fn.__name__}}, tags=tags)
            if input_datasets:
                tracker.read(job, run, inputs=input_datasets, facets={"io": {"from": "decorator"}}, tags=tags)
            try:
                result = fn(*args, **kwargs)
                outs = output_datasets or ()
                if outs:
                    tracker.write(job, run, outputs=outs, facets={"io": {"from": "decorator"}}, tags=tags)
                tracker.complete_run(job, run, outputs=outs, metrics=(), facets={}, tags=tags)
                return result
            except BaseException as ex:
                tracker.fail_run(job, run, ex, facets={"exception": {"type": type(ex).__name__}}, tags=tags)
                raise
        return wrapper
    return decorate

# ---------------------------
# Helpers
# ---------------------------

def _now() -> str:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat().replace("+00:00", "Z")

def _uuid() -> str:
    return str(uuid.uuid4())

def _format_exc(err: Union[str, BaseException]) -> str:
    if isinstance(err, str):
        return err
    tb = "".join(traceback.format_exception(type(err), err, err.__traceback__))
    # Limit to 32k to avoid overgrown records
    return tb[-32768:]

def _dot_id(s: str) -> str:
    return s.replace('"', "'")

def _code_fingerprint(skip_frames: int = 0) -> Mapping[str, Any]:
    try:
        frame = inspect.stack()[skip_frames + 1].frame
        func = frame.f_code
        src = None
        try:
            src = inspect.getsource(frame.f_globals.get(func.co_name))  # type: ignore
        except Exception:
            pass
        payload = {
            "file": func.co_filename,
            "func": func.co_name,
            "firstlineno": func.co_firstlineno,
        }
        text = f"{payload['file']}|{payload['func']}|{payload['firstlineno']}|{src or ''}"
        payload["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return payload
    except Exception:
        return {"file": None, "func": None, "firstlineno": None, "sha256": None}

def _event_to_dict(e: LineageEvent) -> Dict[str, Any]:
    return {
        "eventTime": e.event_time,
        "eventType": e.event_type,
        "producer": e.producer,
        "job": {"namespace": e.job.namespace, "name": e.job.name, "facets": redact(e.job.facets)},
        "run": {"runId": e.run.run_id, "parent": e.run.parent_run_id, "facets": redact(e.run.facets)},
        "inputs": [_ds_to_dict(d) for d in e.inputs],
        "outputs": [_ds_to_dict(d) for d in e.outputs],
        "facets": redact(e.facets),
        "metrics": [dataclasses.asdict(m) for m in e.metrics],
        "tags": list(e.tags),
        "error": e.error,
        "key": e.key(),
    }

def _event_from_dict(d: Mapping[str, Any]) -> LineageEvent:
    job = JobRef(namespace=d["job"]["namespace"], name=d["job"]["name"], facets=d["job"].get("facets") or {})
    run = RunRef(run_id=d["run"]["runId"], parent_run_id=d["run"].get("parent"), facets=d["run"].get("facets") or {})
    ins = [_ds_from_dict(x) for x in d.get("inputs", [])]
    outs = [_ds_from_dict(x) for x in d.get("outputs", [])]
    metrics = [Metric(**m) for m in d.get("metrics", [])]
    return LineageEvent(
        event_time=d["eventTime"],
        event_type=d["eventType"],
        producer=d["producer"],
        job=job,
        run=run,
        inputs=tuple(ins),
        outputs=tuple(outs),
        facets=d.get("facets") or {},
        metrics=tuple(metrics),
        tags=tuple(d.get("tags", [])),
        error=d.get("error"),
    )

def _event_to_openlineage(e: LineageEvent) -> Dict[str, Any]:
    return {
        "eventType": e.event_type,
        "eventTime": e.event_time,
        "producer": e.producer,
        "job": {"namespace": e.job.namespace, "name": e.job.name},
        "run": {"runId": e.run.run_id, **({"parent": {"runId": e.run.parent_run_id}} if e.run.parent_run_id else {})},
        "inputs": [_ds_to_openlineage(d) for d in e.inputs],
        "outputs": [_ds_to_openlineage(d) for d in e.outputs],
        "facets": redact(e.facets),
    }

def _ds_to_dict(d: DatasetRef) -> Dict[str, Any]:
    return {
        "namespace": d.namespace,
        "name": d.name,
        "version": d.version,
        "facets": redact(d.facets),
    }

def _ds_from_dict(d: Mapping[str, Any]) -> DatasetRef:
    return DatasetRef(namespace=d["namespace"], name=d["name"], version=d.get("version"), facets=d.get("facets") or {})

def _ds_to_openlineage(d: DatasetRef) -> Dict[str, Any]:
    out = {"namespace": d.namespace, "name": d.name}
    if d.version is not None:
        out["version"] = d.version
    if d.facets:
        out["facets"] = redact(d.facets)
    return out

def _redact_ds(datasets: Sequence[DatasetRef], cfg: TrackerConfig) -> Sequence[DatasetRef]:
    out = []
    for d in datasets:
        out.append(DatasetRef(d.namespace, d.name, d.version, facets=redact(d.facets, cfg.redact_keys)))
    return tuple(out)

# ---------------------------
# Minimal smoke test
# ---------------------------

if __name__ == "__main__":  # pragma: no cover
    store = SQLiteStore(":memory:")
    tracker = LineageTracker(store)

    orders = DatasetRef("warehouse", "orders", version="v1")
    items = DatasetRef("warehouse", "items", version="v3")
    report = DatasetRef("mart", "daily_report", version="2025-08-15")

    job = JobRef("etl", "daily_aggregation")
    run = tracker.start_run(job, inputs=[orders, items], outputs=[report], facets={"start": {"note": "pipeline start"}})

    tracker.read(job, run, inputs=[orders, items])
    tracker.write(job, run, outputs=[report], facets={"quality": {"rowCount": 12345}})
    tracker.add_metric(job, run, Metric(name="duration_sec", value=12.34))
    tracker.complete_run(job, run, outputs=[report], tags=["prod"])

    tracker.flush()

    events = list(store.read_all())
    print("Events:", len(events))
    print("DOT:")
    print(tracker.export_graph_dot(events))

    @lineage_task(tracker, "ad-hoc", "hello_world", [orders], [report])
    def hello():
        return "ok"

    hello()
    tracker.flush()
