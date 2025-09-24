# datafabric-core/mocks/ingest_source_mock.py
# Industrial-grade ingest source mock for DataFabric
# Features:
# - Deterministic event generation (seeded PRNG) with JSON schema-like spec
# - Sinks: stdout | file | Kafka (optional, via kafka-python) with delivery confirm
# - Rate limiting (RPS), controlled concurrency (threads), graceful shutdown
# - Checkpointing (offset/sequence) to resume, idempotent event_id
# - Chaos: drop_rate, duplicate_rate, jitter_delay_ms
# - Optional masking hook for PII-safe payloads
# - Metrics: produced/ack/failed, lag to wall clock, p50/p95 lat, periodic report
# - Config via CLI and ENV
#
# Schema spec (JSON/YAML-like via JSON):
# {
#   "namespace": "datafabric.mock",
#   "type": "event",
#   "fields": {
#     "event_id": {"gen": "uuid", "deterministic": true},
#     "event_time": {"gen": "now"},
#     "partition_key": {"gen": "choice", "choices": ["eu","us","apac"], "weights": [0.6,0.3,0.1]},
#     "source": {"const": "mock"},
#     "type": {"gen": "choice", "choices": ["signup","purchase","refund"]},
#     "user": {
#       "type": "object",
#       "fields": {
#         "id": {"gen": "seq", "start": 1},
#         "email": {"gen": "email", "domain": "example.com"},
#         "age": {"gen": "int", "min": 18, "max": 80}
#       }
#     },
#     "amount": {"gen": "float", "min": 0, "max": 999.99, "precision": 2},
#     "payload": {"gen": "map", "size": 3}
#   }
# }
#
# ENV (overrides CLI):
#   DF_MOCK_SINK               - stdout|file|kafka
#   DF_MOCK_KAFKA_BOOTSTRAP    - host:port
#   DF_MOCK_KAFKA_TOPIC        - topic name
#   DF_MOCK_FILE_PATH          - output file path
#   DF_MOCK_RPS                - events per second (float)
#   DF_MOCK_THREADS            - worker threads
#   DF_MOCK_SEED               - int seed
#   DF_MOCK_CHECKPOINT         - path to checkpoint file
#   DF_MOCK_DURATION_SEC       - run duration in seconds
#   DF_MOCK_TOTAL              - total events to generate
#   DF_MOCK_DROP_RATE          - 0..1
#   DF_MOCK_DUP_RATE           - 0..1
#   DF_MOCK_JITTER_MS          - max random extra delay per event
#   DF_MOCK_REPORT_EVERY_SEC   - metrics period
#   DF_MOCK_MASKING            - enable masking hook (true/false)
#
# Exit codes: 0 OK, 1 error, 2 sink error

from __future__ import annotations

import argparse
import json
import os
import queue
import random
import signal
import string
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import median
from typing import Any, Dict, Optional, Tuple, List

# ---------- Optional Kafka ----------
try:
    from kafka import KafkaProducer  # type: ignore
    _KAFKA = True
except Exception:
    KafkaProducer = None  # type: ignore
    _KAFKA = False

# ---------- Utils ----------

def utcnow_iso() -> str:
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()

def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

# ---------- Masking hook (no hard dependency on other modules) ----------

def default_masker(field: str, value: Any, params: Dict[str, Any]) -> Any:
    if value is None:
        return None
    # simple email/phone partial masking
    if isinstance(value, str) and "@" in value and field.lower().endswith("email"):
        name, _, dom = value.partition("@")
        keep = max(1, min(3, len(name)//3))
        return name[:keep] + "*"*(len(name)-keep) + "@" + dom
    if field.lower() in ("password","token","secret","api_key","authorization"):
        return "***REDACTED***"
    return value

# ---------- Schema-driven generator ----------

@dataclass
class FieldSpec:
    gen: Optional[str] = None
    const: Optional[Any] = None
    type: Optional[str] = None          # for nested object / array
    fields: Optional[Dict[str, Any]] = None
    choices: Optional[List[Any]] = None
    weights: Optional[List[float]] = None
    min: Optional[float] = None
    max: Optional[float] = None
    precision: Optional[int] = None
    start: Optional[int] = None
    size: Optional[int] = None
    deterministic: bool = False
    domain: Optional[str] = None

@dataclass
class SchemaSpec:
    namespace: str
    type: str
    fields: Dict[str, FieldSpec]

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "SchemaSpec":
        f = {k: FieldSpec(**v) for k, v in d.get("fields", {}).items()}
        return SchemaSpec(namespace=d.get("namespace","datafabric.mock"), type=d.get("type","event"), fields=f)

class DeterministicSeq:
    def __init__(self, start: int = 1):
        self.v = start - 1
        self.lock = threading.Lock()
    def next(self) -> int:
        with self.lock:
            self.v += 1
            return self.v
    def resume(self, to_value: int) -> None:
        with self.lock:
            self.v = max(self.v, to_value)

class EventGenerator:
    def __init__(self, schema: SchemaSpec, seed: int, masker_enabled: bool = False):
        self.schema = schema
        self.rnd = random.Random(seed)
        self.masker_enabled = masker_enabled
        # per-field deterministic sequences
        self.seq_by_field: Dict[str, DeterministicSeq] = {}
        for k, spec in schema.fields.items():
            if spec.gen == "seq":
                self.seq_by_field[k] = DeterministicSeq(start=spec.start or 1)

    def _rand_str(self, n: int) -> str:
        return "".join(self.rnd.choices(string.ascii_letters + string.digits, k=n))

    def _email(self, domain: Optional[str]) -> str:
        name = self._rand_str(self.rnd.randint(5, 10)).lower()
        dom = domain or self.rnd.choice(["example.com","test.local","mail.dev"])
        return f"{name}@{dom}"

    def _choice(self, spec: FieldSpec) -> Any:
        if not spec.choices:
            return None
        if spec.weights and len(spec.weights) == len(spec.choices):
            return self.rnd.choices(spec.choices, weights=spec.weights, k=1)[0]
        return self.rnd.choice(spec.choices)

    def _int(self, spec: FieldSpec) -> int:
        lo = int(spec.min if spec.min is not None else 0)
        hi = int(spec.max if spec.max is not None else 100)
        return self.rnd.randint(lo, hi)

    def _float(self, spec: FieldSpec) -> float:
        lo = float(spec.min if spec.min is not None else 0.0)
        hi = float(spec.max if spec.max is not None else 1.0)
        val = self.rnd.uniform(lo, hi)
        if spec.precision is not None:
            val = round(val, spec.precision)
        return val

    def _map(self, spec: FieldSpec) -> Dict[str, Any]:
        size = spec.size or 3
        return {f"k{i}": self._rand_str(self.rnd.randint(4, 12)) for i in range(size)}

    def _gen_field(self, name: str, spec: FieldSpec, seq_seed: Optional[int] = None) -> Any:
        # constants
        if spec.const is not None:
            return spec.const
        g = (spec.gen or "").lower()
        if g == "uuid":
            # stable if deterministic: hash(namespace|name|seq)
            return str(uuid.UUID(int=self.rnd.getrandbits(128))) if not spec.deterministic else str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{self.schema.namespace}:{name}:{seq_seed or 0}"))
        if g == "now":
            return utcnow_iso()
        if g == "choice":
            return self._choice(spec)
        if g == "int":
            return self._int(spec)
        if g == "float":
            return self._float(spec)
        if g == "seq":
            return self.seq_by_field[name].next()
        if g == "email":
            return self._email(spec.domain)
        if g == "map":
            return self._map(spec)
        # nested object
        if (spec.type or "").lower() == "object" and spec.fields:
            return {k: self._gen_field(f"{name}.{k}", FieldSpec(**v) if isinstance(v, dict) else v, seq_seed=seq_seed) for k, v in spec.fields.items()}
        return None

    def next_event(self, seq: int) -> Dict[str, Any]:
        ev: Dict[str, Any] = {}
        # ensure event_time present
        for k, spec in self.schema.fields.items():
            val = self._gen_field(k, spec, seq_seed=seq)
            if self.masker_enabled:
                val = default_masker(k, val, {"label": k})
            ev[k] = val
        # enrich
        if "event_id" not in ev:
            ev["event_id"] = str(uuid.uuid4()) if not self.schema.fields.get("event_id") else ev["event_id"]
        if "event_time" not in ev:
            ev["event_time"] = utcnow_iso()
        return ev

# ---------- Sinks ----------

class Sink:
    def send(self, key: Optional[str], value: str) -> None:
        raise NotImplementedError
    def flush(self) -> None:
        pass
    def close(self) -> None:
        pass

class StdoutSink(Sink):
    def send(self, key: Optional[str], value: str) -> None:
        print(value, flush=False)

class FileSink(Sink):
    def __init__(self, path: str):
        self.f = open(path, "a", encoding="utf-8")
        self.lock = threading.Lock()
    def send(self, key: Optional[str], value: str) -> None:
        with self.lock:
            self.f.write(value + "\n")
    def flush(self) -> None:
        with self.lock:
            self.f.flush()
    def close(self) -> None:
        with self.lock:
            try:
                self.f.flush()
                self.f.close()
            except Exception:
                pass

class KafkaSink(Sink):
    def __init__(self, bootstrap: str, topic: str):
        if not _KAFKA:
            raise RuntimeError("kafka-python is not installed")
        self.topic = topic
        self.p = KafkaProducer(
            bootstrap_servers=bootstrap,
            acks="all",
            value_serializer=lambda v: v.encode("utf-8"),
            key_serializer=lambda v: v.encode("utf-8") if v is not None else None,
            linger_ms=50,
            compression_type="gzip",
        )
    def send(self, key: Optional[str], value: str) -> None:
        fut = self.p.send(self.topic, key=key, value=value)
        # optional blocking to surface errors
        fut.get(timeout=10)
    def flush(self) -> None:
        self.p.flush()
    def close(self) -> None:
        try:
            self.p.flush(5)
            self.p.close()
        except Exception:
            pass

def build_sink(kind: str, args) -> Sink:
    if kind == "stdout":
        return StdoutSink()
    if kind == "file":
        return FileSink(args.file_path)
    if kind == "kafka":
        return KafkaSink(args.kafka_bootstrap, args.kafka_topic)
    raise ValueError(f"Unsupported sink: {kind}")

# ---------- Metrics ----------

@dataclass
class Metrics:
    produced: int = 0
    sent: int = 0
    failed: int = 0
    dropped: int = 0
    duplicated: int = 0
    lat_ms: List[float] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def inc(self, attr: str, delta: int = 1) -> None:
        with self.lock:
            setattr(self, attr, getattr(self, attr) + delta)

    def add_lat(self, ms: float) -> None:
        with self.lock:
            self.lat_ms.append(ms)
            if len(self.lat_ms) > 1000:
                self.lat_ms = self.lat_ms[-500:]

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            l = list(self.lat_ms)
            p50 = median(l) if l else None
            p95 = sorted(l)[int(0.95 * len(l))] if l else None
            return {
                "produced": self.produced,
                "sent": self.sent,
                "failed": self.failed,
                "dropped": self.dropped,
                "duplicated": self.duplicated,
                "p50_ms": p50,
                "p95_ms": p95,
                "inflight_lat_samples": len(l),
            }

# ---------- Checkpoint ----------

class Checkpoint:
    def __init__(self, path: Optional[str], seed: int):
        self.path = path
        self.seq = 0
        self.seed = seed
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    d = json.load(f)
                    if int(d.get("seed", seed)) == seed:
                        self.seq = int(d.get("seq", 0))
            except Exception:
                pass
        self.lock = threading.Lock()

    def commit(self, seq: int) -> None:
        if not self.path:
            return
        with self.lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"seq": seq, "seed": self.seed, "ts": utcnow_iso()}, f)
            os.replace(tmp, self.path)

# ---------- Producer ----------

class Producer:
    def __init__(self, args, schema: SchemaSpec):
        self.args = args
        self.metrics = Metrics()
        self.stop = threading.Event()
        signal.signal(signal.SIGTERM, self._sig)
        signal.signal(signal.SIGINT, self._sig)
        self.rnd = random.Random(args.seed)
        self.sink = build_sink(args.sink, args)
        self.gen = EventGenerator(schema, seed=args.seed, masker_enabled=args.masking)
        self.chkpt = Checkpoint(args.checkpoint, seed=args.seed)
        self.seq = self.chkpt.seq
        self.q: "queue.Queue[Tuple[Optional[str], str]]" = queue.Queue(maxsize=args.threads * 1000)

    def _sig(self, signum, frame):
        self.stop.set()

    def _maybe_sleep_for_rps(self, last_t: float, events: int) -> float:
        if self.args.rps <= 0:
            return time.monotonic()
        expected_elapsed = events / self.args.rps
        elapsed = time.monotonic() - last_t
        if elapsed < expected_elapsed:
            time.sleep(expected_elapsed - elapsed)
        return time.monotonic()

    def _worker(self, wid: int):
        while not self.stop.is_set():
            try:
                key, val = self.q.get(timeout=0.2)
            except queue.Empty:
                continue
            t0 = time.monotonic()
            try:
                self.sink.send(key, val)
                self.metrics.inc("sent", 1)
                self.metrics.add_lat((time.monotonic() - t0) * 1000.0)
            except Exception:
                self.metrics.inc("failed", 1)
            finally:
                self.q.task_done()

    def run(self) -> int:
        # workers
        threads = []
        for i in range(self.args.threads):
            t = threading.Thread(target=self._worker, args=(i,), daemon=True, name=f"worker-{i}")
            t.start()
            threads.append(t)

        start = time.monotonic()
        last_t = start
        produced_since_tick = 0
        total_target = self.args.total if self.args.total > 0 else None
        duration_target = self.args.duration if self.args.duration > 0 else None
        next_report = start + self.args.report_every

        try:
            while not self.stop.is_set():
                # stop conditions
                if total_target is not None and self.metrics.produced >= total_target:
                    break
                if duration_target is not None and (time.monotonic() - start) >= duration_target:
                    break

                # chaos control
                if self.rnd.random() < self.args.drop_rate:
                    # dropped before generation (simulates source loss)
                    self.metrics.inc("dropped", 1)
                    continue

                # generate
                self.seq += 1
                ev = self.gen.next_event(self.seq)
                self.metrics.inc("produced", 1)

                # partition key
                pkey = str(ev.get("partition_key")) if ev.get("partition_key") is not None else None

                # duplicate?
                if self.rnd.random() < self.args.dup_rate:
                    self.metrics.inc("duplicated", 1)
                    dup = dict(ev)
                    # same event_id for exact duplicate; or tweak:
                    # dup["event_time"] = utcnow_iso()
                    self._enqueue(pkey, json.dumps(dup, ensure_ascii=False))
                # jitter
                if self.args.jitter_ms > 0:
                    time.sleep(self.rnd.uniform(0, self.args.jitter_ms) / 1000.0)

                # enqueue
                self._enqueue(pkey, json.dumps(ev, ensure_ascii=False))

                produced_since_tick += 1
                last_t = self._maybe_sleep_for_rps(last_t, produced_since_tick)

                # checkpoint occasionally
                if self.seq % max(1000, int(self.args.rps) if self.args.rps > 0 else 1000) == 0:
                    self.chkpt.commit(self.seq)

                # metrics report
                now = time.monotonic()
                if now >= next_report:
                    snap = self.metrics.snapshot()
                    snap["qsize"] = self.q.qsize()
                    snap["seq"] = self.seq
                    print(f"[mock] {json.dumps(snap, ensure_ascii=False)}", file=sys.stderr, flush=True)
                    next_report = now + self.args.report_every
                    produced_since_tick = 0

            # drain
            self.chkpt.commit(self.seq)
            self.q.join()
            self.sink.flush()
            return 0
        except Exception as e:
            print(f"[mock] error: {e}", file=sys.stderr)
            return 1
        finally:
            try:
                self.sink.close()
            except Exception:
                pass
            self.stop.set()

    def _enqueue(self, key: Optional[str], value: str) -> None:
        while not self.stop.is_set():
            try:
                self.q.put((key, value), timeout=0.2)
                return
            except queue.Full:
                # backpressure: brief sleep
                time.sleep(0.01)

# ---------- CLI ----------

def parse_schema(path: Optional[str]) -> SchemaSpec:
    if not path:
        # default schema
        d = {
            "namespace": "datafabric.mock",
            "type": "event",
            "fields": {
                "event_id": {"gen": "uuid", "deterministic": True},
                "event_time": {"gen": "now"},
                "partition_key": {"gen": "choice", "choices": ["eu","us","apac"], "weights": [0.6,0.3,0.1]},
                "source": {"const": "mock"},
                "type": {"gen": "choice", "choices": ["signup","purchase","refund"]},
                "user": {
                    "type": "object",
                    "fields": {
                        "id": {"gen": "seq", "start": 1},
                        "email": {"gen": "email", "domain": "example.com"},
                        "age": {"gen": "int", "min": 18, "max": 80}
                    }
                },
                "amount": {"gen": "float", "min": 0, "max": 999.99, "precision": 2},
                "payload": {"gen": "map", "size": 3}
            }
        }
        return SchemaSpec.from_dict(d)
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
        # Accept JSON only to avoid extra deps
        d = json.loads(text)
        return SchemaSpec.from_dict(d)

def parse_args(argv: Optional[List[str]] = None):
    p = argparse.ArgumentParser(description="DataFabric ingest source mock")
    p.add_argument("--sink", choices=["stdout","file","kafka"], default=os.getenv("DF_MOCK_SINK","stdout"))
    p.add_argument("--kafka-bootstrap", default=os.getenv("DF_MOCK_KAFKA_BOOTSTRAP"))
    p.add_argument("--kafka-topic", default=os.getenv("DF_MOCK_KAFKA_TOPIC"))
    p.add_argument("--file-path", default=os.getenv("DF_MOCK_FILE_PATH","./mock-events.jsonl"))
    p.add_argument("--schema", help="path to schema JSON file")
    p.add_argument("--rps", type=float, default=float(os.getenv("DF_MOCK_RPS","100.0")))
    p.add_argument("--threads", type=int, default=int(os.getenv("DF_MOCK_THREADS","4")))
    p.add_argument("--seed", type=int, default=int(os.getenv("DF_MOCK_SEED","42")))
    p.add_argument("--checkpoint", default=os.getenv("DF_MOCK_CHECKPOINT","./mock-checkpoint.json"))
    p.add_argument("--duration", type=float, default=float(os.getenv("DF_MOCK_DURATION_SEC","0")))
    p.add_argument("--total", type=int, default=int(os.getenv("DF_MOCK_TOTAL","0")))
    p.add_argument("--drop-rate", type=float, default=float(os.getenv("DF_MOCK_DROP_RATE","0.0")))
    p.add_argument("--dup-rate", type=float, default=float(os.getenv("DF_MOCK_DUP_RATE","0.0")))
    p.add_argument("--jitter-ms", type=int, default=int(os.getenv("DF_MOCK_JITTER_MS","0")))
    p.add_argument("--report-every", type=float, default=float(os.getenv("DF_MOCK_REPORT_EVERY_SEC","5.0")))
    p.add_argument("--masking", action="store_true", default=os.getenv("DF_MOCK_MASKING","false").lower() in ("1","true","yes"))
    args = p.parse_args(argv)

    # validations
    if args.sink == "kafka":
        if not args.kafka_bootstrap or not args.kafka_topic:
            p.error("--kafka-bootstrap and --kafka-topic are required for sink=kafka")
        if not _KAFKA:
            p.error("kafka-python is not installed but sink=kafka requested")
    args.rps = clamp(args.rps, 0.0, 1e6)
    args.threads = max(1, args.threads)
    args.drop_rate = clamp(args.drop_rate, 0.0, 1.0)
    args.dup_rate = clamp(args.dup_rate, 0.0, 1.0)
    return args

def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    schema = parse_schema(args.schema)
    prod = Producer(args, schema)
    rc = prod.run()
    return rc

if __name__ == "__main__":
    sys.exit(main())
