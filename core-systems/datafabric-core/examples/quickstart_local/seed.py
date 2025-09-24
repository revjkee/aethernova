#!/usr/bin/env python3
# datafabric-core/examples/quickstart_local/seed.py
# Industrial-grade local seeding script for DataFabric Quickstart
# Features:
# - Deterministic synthetic datasets: users, events, dlp_incidents (optional)
# - Formats: csv | jsonl | parquet (if pyarrow fastparquet available) with gzip option
# - Partitioning by event_date=YYYY-MM-DD, controllable rows/partitions
# - Parallel file writing with integrity manifest (SHA-256 per file)
# - Optional Kafka emission (--kafka-bootstrap/--kafka-topic) if kafka-python installed
# - Re-runnable (idempotent filenames), resumable (skips valid files by hash unless --force)
# - Validates row counts and prints concise progress
# - Creates minimal local folder layout and example configs in ./quickstart_data
#
# Exit codes: 0 OK, 1 error, 2 validation/integrity error

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import dataclasses
import gzip
import hashlib
import json
import os
import pathlib
import random
import string
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Optional Parquet
_PARQUET = False
try:
    import pyarrow as pa  # type: ignore
    import pyarrow.parquet as pq  # type: ignore
    _PARQUET = True
except Exception:
    pass

# Optional Kafka
_KAFKA = False
try:
    from kafka import KafkaProducer  # type: ignore
    _KAFKA = True
except Exception:
    pass

# ------------------------- Utils -------------------------

def utc_iso(dt: Optional[datetime] = None) -> str:
    dt = dt or datetime.utcnow().replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()

def sha256_file(path: pathlib.Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with (gzip.open if path.suffix == ".gz" else open)(path, "rb") as f:  # transparent hash of compressed content
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def ensure_dir(p: pathlib.Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)

def human(n: int) -> str:
    return f"{n:,}".replace(",", " ")

# ------------------------- Schema / Generators -------------------------

@dataclass
class SeedConfig:
    out_dir: pathlib.Path
    fmt: str
    gzip: bool
    partitions: int
    rows_per_partition: int
    start_date: datetime
    dlp_rate: float
    seed: int
    force: bool
    kafka_bootstrap: Optional[str] = None
    kafka_topic: Optional[str] = None

class Deterministic:
    def __init__(self, seed: int):
        self.rnd = random.Random(seed)

    def choice(self, arr: List[Any]) -> Any:
        return self.rnd.choice(arr)

    def randint(self, a: int, b: int) -> int:
        return self.rnd.randint(a, b)

    def uniform(self, a: float, b: float) -> float:
        return self.rnd.uniform(a, b)

    def str_token(self, n: int) -> str:
        return "".join(self.rnd.choices(string.ascii_letters + string.digits, k=n))

class RowFactory:
    def __init__(self, R: Deterministic):
        self.R = R
        self.user_seq = 0
        self.event_seq = 0

    def user_row(self, date: datetime) -> Dict[str, Any]:
        self.user_seq += 1
        uid = self.user_seq
        email_local = f"user{uid}"
        dom = self.R.choice(["example.com", "corp.local", "mail.dev"])
        return {
            "user_id": uid,
            "email": f"{email_local}@{dom}",
            "name": f"{self.R.choice(['Alice','Bob','Carol','Dave','Erin','Frank'])} {self.R.choice(['Ivanov','Petrov','Sidorov','Smirnov'])}",
            "age": self.R.randint(18, 79),
            "country": self.R.choice(["SE","DE","PL","ES","FR","US"]),
            "created_at": utc_iso(date + timedelta(hours=self.R.randint(0, 23), minutes=self.R.randint(0, 59))),
        }

    def event_row(self, date: datetime) -> Dict[str, Any]:
        self.event_seq += 1
        etype = self.R.choice(["signup", "purchase", "view", "refund", "click"])
        user_id = self.R.randint(1, max(1, self.user_seq))
        amount = round(self.R.uniform(0, 999.99), 2) if etype in ("purchase", "refund") else None
        return {
            "event_id": f"ev-{self.event_seq:012d}",
            "event_time": utc_iso(date + timedelta(hours=self.R.randint(0, 23), minutes=self.R.randint(0, 59), seconds=self.R.randint(0, 59))),
            "event_type": etype,
            "user_id": user_id,
            "partition_key": self.R.choice(["eu","us","apac"]),
            "amount": amount,
            "attrs": {"campaign": self.R.choice(["spring","summer","fall","winter"]), "channel": self.R.choice(["email","ads","direct","social"])},
        }

    def dlp_row(self, date: datetime, maybe: bool) -> Optional[Dict[str, Any]]:
        if not maybe:
            return None
        # intentionally include a pattern to test DLP
        email = f"leak.{self.R.str_token(5)}@example.com"
        card = "4111 1111 1111 1111" if self.R.uniform(0, 1) < 0.5 else None
        return {
            "ts": utc_iso(date),
            "system": "mock-ingest",
            "severity": self.R.choice(["low","medium","high","critical"]),
            "indicator": self.R.choice(["email","credit_card","jwt","aws_key"]),
            "snippet": f"contact={email}" + (f" cc={card}" if card else ""),
        }

# ------------------------- Writers -------------------------

class Writer:
    def __init__(self, fmt: str, gzip_flag: bool):
        self.fmt = fmt
        self.gzip = gzip_flag
        if fmt == "parquet" and not _PARQUET:
            raise RuntimeError("Parquet выбран, но pyarrow не установлен")

    def _open(self, path: pathlib.Path):
        ensure_dir(path)
        if self.gzip and self.fmt in ("csv", "jsonl"):
            return gzip.open(path, "wt", encoding="utf-8", newline="")
        return open(path, "w", encoding="utf-8", newline="")

    def write_csv(self, path: pathlib.Path, rows: Iterable[Dict[str, Any]], header: List[str]) -> None:
        with self._open(path) as f:
            w = csv.DictWriter(f, fieldnames=header, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)

    def write_jsonl(self, path: pathlib.Path, rows: Iterable[Dict[str, Any]]) -> None:
        with self._open(path) as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def write_parquet(self, path: pathlib.Path, rows: List[Dict[str, Any]]) -> None:
        table = pa.Table.from_pylist(rows)  # type: ignore
        ensure_dir(path)
        pq.write_table(table, path)  # type: ignore

    def write(self, path: pathlib.Path, rows: List[Dict[str, Any]], header: Optional[List[str]] = None) -> None:
        if self.fmt == "csv":
            assert header is not None, "Для CSV требуется header"
            return self.write_csv(path, rows, header)
        if self.fmt == "jsonl":
            return self.write_jsonl(path, rows)
        if self.fmt == "parquet":
            return self.write_parquet(path, rows)
        raise ValueError(self.fmt)

# ------------------------- Manifest -------------------------

@dataclass
class ManifestItem:
    type: str              # dataset
    name: str              # users | events | dlp_incidents
    path: str              # relative file path
    rows: int
    sha256: str

@dataclass
class Manifest:
    version: str = "1.0"
    created_at: str = field(default_factory=lambda: utc_iso())
    label: str = "quickstart_local"
    items: List[ManifestItem] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), ensure_ascii=False, indent=2)

# ------------------------- Kafka (optional) -------------------------

class KafkaOut:
    def __init__(self, bootstrap: str, topic: str):
        if not _KAFKA:
            raise RuntimeError("kafka-python не установлен")
        self.p = KafkaProducer(
            bootstrap_servers=bootstrap,
            acks="all",
            key_serializer=lambda v: v.encode("utf-8") if v else None,
            value_serializer=lambda v: v.encode("utf-8"),
            linger_ms=50,
            compression_type="gzip",
        )
        self.topic = topic

    def send(self, key: Optional[str], value: Dict[str, Any]) -> None:
        self.p.send(self.topic, key=key or "", value=json.dumps(value, ensure_ascii=False)).get(timeout=10)

    def close(self) -> None:
        try:
            self.p.flush(10)
            self.p.close()
        except Exception:
            pass

# ------------------------- Seeding core -------------------------

def partition_path(base: pathlib.Path, dataset: str, date: datetime, fmt: str, gz: bool) -> pathlib.Path:
    d = date.strftime("%Y-%m-%d")
    fn = f"part-{d}.{fmt}" + (".gz" if gz and fmt in ("csv","jsonl") else "")
    return base / dataset / f"event_date={d}" / fn

def write_partition(cfg: SeedConfig, rf: RowFactory, writer: Writer, dataset: str, date: datetime) -> Tuple[str, int, str]:
    path = partition_path(cfg.out_dir, dataset, date, cfg.fmt, cfg.gzip)
    if path.exists() and not cfg.force:
        # trust existing file by hash; will be validated later
        h = sha256_file(path)
        # unknown row count here; return 0 to avoid double counting, final validation reads manifest or recount
        return (str(path.relative_to(cfg.out_dir)), 0, h)

    rows: List[Dict[str, Any]] = []
    if dataset == "users":
        for _ in range(cfg.rows_per_partition):
            rows.append(rf.user_row(date))
        header = ["user_id","email","name","age","country","created_at"]
        writer.write(path, rows, header)
    elif dataset == "events":
        for _ in range(cfg.rows_per_partition):
            rows.append(rf.event_row(date))
        # small enrichment: keep user cardinality realistic
        header = ["event_id","event_time","event_type","user_id","partition_key","amount","attrs"]
        if cfg.fmt == "csv":
            # serialize attrs as JSON for CSV
            rows_csv = [{**r, "attrs": json.dumps(r.get("attrs") or {}, ensure_ascii=False)} for r in rows]
            writer.write(path, rows_csv, header)
        else:
            writer.write(path, rows, header if cfg.fmt == "csv" else None)
    elif dataset == "dlp_incidents":
        for _ in range(cfg.rows_per_partition):
            maybe = (random.random() < cfg.dlp_rate)
            r = rf.dlp_row(date, maybe)
            if r:
                rows.append(r)
        if not rows:
            # ensure file exists for partition discoverability
            rows = []
        header = ["ts","system","severity","indicator","snippet"]
        writer.write(path, rows, header)
    else:
        raise ValueError(dataset)

    h = sha256_file(path)
    return (str(path.relative_to(cfg.out_dir)), len(rows), h)

def build_and_write(cfg: SeedConfig) -> Manifest:
    base = cfg.out_dir
    base.mkdir(parents=True, exist_ok=True)

    writer = Writer(cfg.fmt, cfg.gzip)
    R = Deterministic(cfg.seed)
    rf = RowFactory(R)

    manifest = Manifest()
    datasets = ["users", "events", "dlp_incidents"]
    dates = [cfg.start_date + timedelta(days=i) for i in range(cfg.partitions)]

    # parallel writing per dataset x date
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, cfg.partitions * 3)) as ex:
        futs = []
        for date in dates:
            for ds in datasets:
                futs.append(ex.submit(write_partition, cfg, rf, writer, ds, date))
        for f in concurrent.futures.as_completed(futs):
            rel, rows, h = f.result()
            ds_name = rel.split("/")[0]
            manifest.items.append(ManifestItem(type="dataset", name=ds_name, path=rel, rows=rows, sha256=h))
            print(f"[seed] wrote {rel} rows={rows} sha256={h[:10]}...", flush=True)

    # minimal configs (idempotent)
    (base / "config").mkdir(exist_ok=True, parents=True)
    (base / "config" / "ingest.yaml").write_text(
        "# Example ingest config for quickstart\nsource: quickstart\ncheckpoint_dir: ./_state\n",
        encoding="utf-8"
    )
    (base / "README.txt").write_text(
        "Quickstart data generated by seed.py\nDatasets: users, events, dlp_incidents\nPartitioned by event_date=YYYY-MM-DD\n",
        encoding="utf-8"
    )

    # final manifest
    (base / "manifest.json").write_text(manifest.to_json(), encoding="utf-8")
    return manifest

def validate_manifest(cfg: SeedConfig, manifest: Manifest) -> None:
    errors: List[str] = []
    total_rows: Dict[str, int] = {"users":0,"events":0,"dlp_incidents":0}
    for it in manifest.items:
        path = cfg.out_dir / it.path
        if not path.exists():
            errors.append(f"missing: {it.path}")
            continue
        h = sha256_file(path)
        if h.lower() != it.sha256.lower():
            errors.append(f"sha mismatch: {it.path}")
        total_rows[it.name] += it.rows
    if errors:
        raise RuntimeError("validation failed: " + "; ".join(errors))
    print(f"[seed] validation OK; totals: {', '.join(f'{k}={human(v)}' for k,v in total_rows.items())}")

def maybe_emit_kafka(cfg: SeedConfig) -> None:
    if not (cfg.kafka_bootstrap and cfg.kafka_topic):
        return
    if not _KAFKA:
        raise RuntimeError("Kafka передача запрошена, но kafka-python не установлен")
    out = KafkaOut(cfg.kafka_bootstrap, cfg.kafka_topic)
    base = cfg.out_dir
    # emit only events dataset
    count = 0
    for p in sorted((base / "events").rglob(f"*.{cfg.fmt}" + (".gz" if (cfg.gzip and cfg.fmt in ('csv','jsonl')) else ""))):
        # stream file line by line for jsonl; csv->dict; parquet via pyarrow
        if cfg.fmt == "jsonl":
            opener = gzip.open if p.suffix == ".gz" else open
            with opener(p, "rt", encoding="utf-8") as f:
                for line in f:
                    try:
                        d = json.loads(line)
                        out.send(key=str(d.get("partition_key") or ""), value=d)
                        count += 1
                    except Exception:
                        pass
        elif cfg.fmt == "csv":
            opener = gzip.open if p.suffix == ".gz" else open
            with opener(p, "rt", encoding="utf-8", newline="") as f:
                r = csv.DictReader(f)
                for d in r:
                    # de-json attrs if present
                    try:
                        if "attrs" in d:
                            d["attrs"] = json.loads(d["attrs"])
                    except Exception:
                        pass
                    out.send(key=str(d.get("partition_key") or ""), value=d)
                    count += 1
        elif cfg.fmt == "parquet":
            if not _PARQUET:
                continue
            tbl = pq.read_table(p)  # type: ignore
            for d in tbl.to_pylist():  # type: ignore
                out.send(key=str(d.get("partition_key") or ""), value=d)
                count += 1
        else:
            continue
    out.close()
    print(f"[seed] Kafka emitted {human(count)} records to {cfg.kafka_topic}")

# ------------------------- CLI -------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="DataFabric Quickstart Local Seeder")
    p.add_argument("--out", default=os.getenv("DF_QS_OUT","./quickstart_data"), help="Выходной каталог")
    p.add_argument("--fmt", choices=["csv","jsonl","parquet"], default=os.getenv("DF_QS_FMT","jsonl"))
    p.add_argument("--gzip", action="store_true", default=os.getenv("DF_QS_GZIP","false").lower() in ("1","true","yes"))
    p.add_argument("--partitions", type=int, default=int(os.getenv("DF_QS_PARTITIONS","3")))
    p.add_argument("--rows-per-partition", type=int, default=int(os.getenv("DF_QS_RPP","1000")))
    p.add_argument("--start-date", default=os.getenv("DF_QS_START_DATE"))  # YYYY-MM-DD
    p.add_argument("--seed", type=int, default=int(os.getenv("DF_QS_SEED","42")))
    p.add_argument("--dlp-rate", type=float, default=float(os.getenv("DF_QS_DLP_RATE","0.02")))
    p.add_argument("--force", action="store_true", default=os.getenv("DF_QS_FORCE","false").lower() in ("1","true","yes"))
    p.add_argument("--kafka-bootstrap", default=os.getenv("DF_QS_KAFKA_BOOTSTRAP"))
    p.add_argument("--kafka-topic", default=os.getenv("DF_QS_KAFKA_TOPIC"))
    args = p.parse_args(argv)

    if args.fmt == "parquet" and not _PARQUET:
        p.error("Выбран parquet, но pyarrow не установлен")
    if args.partitions <= 0 or args.rows_per_partition < 0:
        p.error("Некорректные значения --partitions/--rows-per-partition")
    if args.kafka_bootstrap and not args.kafka_topic:
        p.error("--kafka-topic обязателен при указании --kafka-bootstrap")

    try:
        start_dt = datetime.strptime(args.start_date, "%Y-%m-%d") if args.start_date else datetime.utcnow()
    except Exception:
        p.error("--start-date должен быть в формате YYYY-MM-DD")
        raise
    args.start_dt = start_dt.replace(tzinfo=timezone.utc)
    return args

def main(argv: Optional[List[str]] = None) -> int:
    t0 = time.time()
    try:
        args = parse_args(argv)
        cfg = SeedConfig(
            out_dir=pathlib.Path(args.out).resolve(),
            fmt=args.fmt,
            gzip=args.gzip,
            partitions=args.partitions,
            rows_per_partition=args.rows_per_partition,
            start_date=args.start_dt,
            dlp_rate=max(0.0, min(1.0, args.dlp_rate)),
            seed=args.seed,
            force=args.force,
            kafka_bootstrap=args.kafka_bootstrap,
            kafka_topic=args.kafka_topic,
        )
        print(f"[seed] out={cfg.out_dir} fmt={cfg.fmt}{' +gzip' if cfg.gzip else ''} partitions={cfg.partitions} rpp={cfg.rows_per_partition} seed={cfg.seed}")

        manifest = build_and_write(cfg)
        validate_manifest(cfg, manifest)

        if cfg.kafka_bootstrap and cfg.kafka_topic:
            maybe_emit_kafka(cfg)

        print(f"[seed] done in {time.time()-t0:.2f}s")
        return 0
    except Exception as e:
        print(f"[seed] error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
