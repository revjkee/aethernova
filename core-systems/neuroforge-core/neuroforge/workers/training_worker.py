# neuroforge-core/neuroforge/workers/training_worker.py
# © NeuroCity / NeuroForge. Industrial-grade training worker.
# Standard library only (optional PyTorch if installed). No external hard deps.

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import datetime as dt
import functools
import importlib
import json
import logging
import logging.handlers
import os
import queue
import random
import signal
import socket
import sys
import threading
import time
import traceback
import types
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, Literal, Optional, Protocol, Tuple

# ---------------------------
# Utilities: time & json
# ---------------------------

ISO = "%Y-%m-%dT%H:%M:%S.%fZ"


def utcnow() -> str:
    return dt.datetime.utcnow().strftime(ISO)


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ---------------------------
# Structured logging
# ---------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": dt.datetime.utcnow().strftime(ISO),
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        # Merge extras
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            base.update(record.extra)
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        return json_dumps(base)


def setup_logging(log_dir: Path, level: str = "INFO") -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(JsonFormatter())
    root.addHandler(ch)

    # Rotating file
    fh = logging.handlers.RotatingFileHandler(
        log_dir / "training_worker.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
    fh.setFormatter(JsonFormatter())
    root.addHandler(fh)


log = logging.getLogger("neuroforge.training_worker")


# ---------------------------
# Metrics (Prometheus text)
# ---------------------------

@dataclasses.dataclass
class Counter:
    name: str
    help: str
    value: float = 0.0

    def inc(self, v: float = 1.0) -> None:
        self.value += v


@dataclasses.dataclass
class Gauge:
    name: str
    help: str
    value: float = 0.0

    def set(self, v: float) -> None:
        self.value = v


class MetricsRegistry:
    def __init__(self) -> None:
        self.counters: Dict[str, Counter] = {}
        self.gauges: Dict[str, Gauge] = {}
        self._lock = threading.Lock()

    def counter(self, name: str, help: str) -> Counter:
        with self._lock:
            return self.counters.setdefault(name, Counter(name, help))

    def gauge(self, name: str, help: str) -> Gauge:
        with self._lock:
            return self.gauges.setdefault(name, Gauge(name, help))

    def render_text(self) -> str:
        lines: list[str] = []
        with self._lock:
            for c in self.counters.values():
                lines.append(f"# HELP {c.name} {c.help}")
                lines.append(f"# TYPE {c.name} counter")
                lines.append(f"{c.name} {c.value}")
            for g in self.gauges.values():
                lines.append(f"# HELP {g.name} {g.help}")
                lines.append(f"# TYPE {g.name} gauge")
                lines.append(f"{g.name} {g.value}")
        return "\n".join(lines) + "\n"


METRICS = MetricsRegistry()
M_JOBS_TOTAL = METRICS.counter("neuroforge_jobs_total", "Total jobs picked by worker")
M_JOBS_OK = METRICS.counter("neuroforge_jobs_succeeded_total", "Jobs succeeded")
M_JOBS_FAIL = METRICS.counter("neuroforge_jobs_failed_total", "Jobs failed")
M_RUNNING = METRICS.gauge("neuroforge_jobs_running", "Currently running jobs")
M_LOOP_LAT = METRICS.gauge("neuroforge_loop_iteration_seconds", "Loop iteration seconds")


# ---------------------------
# Health & metrics HTTP server
# ---------------------------

class _Handler(BaseHTTPRequestHandler):
    registry: MetricsRegistry = METRICS
    health_state = {"status": "ok", "ts": utcnow()}
    server_version = "NeuroForgeWorker/1.0"
    sys_version = ""

    def do_GET(self) -> None:
        if self.path.startswith("/healthz"):
            payload = json_dumps(self.health_state).encode("utf-8")
            self._reply(200, "application/json", payload)
            return
        if self.path.startswith("/metrics"):
            text = self.registry.render_text().encode("utf-8")
            self._reply(200, "text/plain; version=0.0.4", text)
            return
        self._reply(404, "text/plain", b"not found\n")

    def log_message(self, fmt: str, *args: Any) -> None:
        # Silence BaseHTTPRequestHandler noisy logs
        log.debug("http", extra={"extra": {"client": self.client_address[0], "path": self.path}})

    def _reply(self, code: int, ctype: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class HttpServerThread(threading.Thread):
    def __init__(self, host: str, port: int) -> None:
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.httpd: Optional[HTTPServer] = None

    def run(self) -> None:
        server_address = (self.host, self.port)
        self.httpd = HTTPServer(server_address, _Handler)
        log.info("http_server_started", extra={"extra": {"host": self.host, "port": self.port}})
        try:
            self.httpd.serve_forever(poll_interval=0.5)
        except Exception:
            log.exception("http_server_error")
        finally:
            log.info("http_server_stopped")

    def shutdown(self) -> None:
        if self.httpd:
            self.httpd.shutdown()


# ---------------------------
# Job model & file queue
# ---------------------------

JobState = Literal["ready", "running", "done", "failed"]

@dataclasses.dataclass
class JobConfig:
    id: str
    created_at: str
    trainer: str                      # e.g. "builtin:sgd_linear" or "package.module:func"
    params: Dict[str, Any]
    attempt: int = 0
    max_retries: int = 3
    backoff_seconds: float = 5.0
    checkpoint: Optional[Dict[str, Any]] = None  # persisted training state

    @staticmethod
    def from_path(path: Path) -> "JobConfig":
        data = read_json(path)
        required = ("id", "created_at", "trainer", "params")
        for r in required:
            if r not in data:
                raise ValueError(f"Job file missing '{r}'")
        return JobConfig(
            id=data["id"],
            created_at=data["created_at"],
            trainer=data["trainer"],
            params=data.get("params", {}),
            attempt=int(data.get("attempt", 0)),
            max_retries=int(data.get("max_retries", 3)),
            backoff_seconds=float(data.get("backoff_seconds", 5.0)),
            checkpoint=data.get("checkpoint"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class FileQueue:
    """
    Filesystem-backed queue with atomic state transitions:
      ready/ -> running/ -> {done/, failed/}
    Each job is a single JSON file. Claim is atomic via os.replace.
    """
    def __init__(self, root: Path) -> None:
        self.root = root
        self.ready = self.root / "ready"
        self.running = self.root / "running"
        self.done = self.root / "done"
        self.failed = self.root / "failed"
        for d in (self.ready, self.running, self.done, self.failed):
            d.mkdir(parents=True, exist_ok=True)

    def _list_sorted(self, dir_: Path) -> Iterable[Path]:
        return sorted(p for p in dir_.glob("*.json"))

    def reclaim_stale(self, stale_seconds: float = 900.0) -> int:
        """
        Move stale running jobs back to ready if their mtime is too old.
        """
        now = time.time()
        n = 0
        for p in self._list_sorted(self.running):
            try:
                if (now - p.stat().st_mtime) > stale_seconds:
                    target = self.ready / p.name
                    os.replace(p, target)
                    n += 1
                    log.warning("reclaim_stale_job", extra={"extra": {"job_file": str(target)}})
            except FileNotFoundError:
                pass
        return n

    def claim(self) -> Optional[Tuple[Path, Path]]:
        """
        Atomically move first job from ready -> running. Return (src,dst).
        """
        for p in self._list_sorted(self.ready):
            running_name = f"{p.stem}.{os.getpid()}-{uuid.uuid4().hex}.json"
            dst = self.running / running_name
            try:
                os.replace(p, dst)
                return (p, dst)
            except FileNotFoundError:
                continue
            except PermissionError:
                continue
        return None

    def complete(self, running_path: Path, success: bool) -> Path:
        """
        Move running job to done or failed.
        """
        target_dir = self.done if success else self.failed
        target = target_dir / running_path.name
        os.replace(running_path, target)
        return target


# ---------------------------
# Trainer protocol & builtin trainers
# ---------------------------

class TrainResult(Dict[str, Any]):
    """
    Keys:
      status: "ok" | "failed"
      epochs: int
      metrics: dict
      checkpoint: dict | None
    """


class Trainer(Protocol):
    def __call__(self, job: JobConfig, log_ctx: Dict[str, Any]) -> TrainResult: ...


def _load_trainer(entry: str) -> Trainer:
    if entry.startswith("builtin:"):
        name = entry.split(":", 1)[1]
        if name == "sgd_linear":
            return builtin_sgd_linear
        if name == "torch_classifier":
            return builtin_torch_classifier
        raise ValueError(f"Unknown builtin trainer '{name}'")
    if ":" in entry:
        mod, func = entry.split(":", 1)
    else:
        mod, func = entry, "train"
    m = importlib.import_module(mod)
    t = getattr(m, func)
    if not callable(t):
        raise TypeError("Trainer entrypoint is not callable")
    return t  # type: ignore[return-value]


def _get_int(d: Dict[str, Any], key: str, default: int) -> int:
    try:
        return int(d.get(key, default))
    except Exception:
        return default


def _get_float(d: Dict[str, Any], key: str, default: float) -> float:
    try:
        return float(d.get(key, default))
    except Exception:
        return default


def builtin_sgd_linear(job: JobConfig, log_ctx: Dict[str, Any]) -> TrainResult:
    """
    Pure-Python toy trainer (no deps). Minimizes MSE for y = a*x + b + noise
    using SGD to demonstrate end-to-end flow, checkpoints, and metrics.
    """
    params = job.params or {}
    epochs = _get_int(params, "epochs", 25)
    steps_per_epoch = _get_int(params, "steps_per_epoch", 200)
    lr = _get_float(params, "lr", 0.01)
    noise = _get_float(params, "noise", 0.1)
    seed = _get_int(params, "seed", 42)
    random.seed(seed)

    # Model parameters
    a = random.uniform(-0.5, 0.5)
    b = random.uniform(-0.5, 0.5)

    # Resume from checkpoint if present
    if job.checkpoint:
        a = float(job.checkpoint.get("a", a))
        b = float(job.checkpoint.get("b", b))
        start_epoch = int(job.checkpoint.get("epoch", 0))
    else:
        start_epoch = 0

    def gen_sample() -> Tuple[float, float]:
        x = random.uniform(-1.0, 1.0)
        y = 2.0 * x + 0.5 + random.gauss(0.0, noise)  # ground truth: a*=2.0, b*=0.5
        return x, y

    total_loss = 0.0
    for epoch in range(start_epoch, epochs):
        epoch_loss = 0.0
        for _ in range(steps_per_epoch):
            x, y = gen_sample()
            y_hat = a * x + b
            err = y_hat - y
            # gradients
            da = 2.0 * err * x
            db = 2.0 * err
            a -= lr * da
            b -= lr * db
            epoch_loss += err * err
        epoch_loss /= steps_per_epoch
        total_loss = epoch_loss
        log.info("train_epoch",
                 extra={"extra": {**log_ctx, "epoch": epoch + 1, "loss_mse": round(epoch_loss, 6)}})
        # Example checkpoint every epoch
        checkpoint = {"epoch": epoch + 1, "a": a, "b": b}
        # Return latest checkpoint via result (worker persists it)
    return TrainResult(
        status="ok",
        epochs=epochs,
        metrics={"loss_mse": float(total_loss), "a": float(a), "b": float(b)},
        checkpoint={"epoch": epochs, "a": a, "b": b},
    )


def builtin_torch_classifier(job: JobConfig, log_ctx: Dict[str, Any]) -> TrainResult:
    """
    Optional PyTorch trainer. If torch is not available, gracefully fallback.
    Trains a tiny MLP on synthetic binary data for a few epochs.
    """
    try:
        import math
        import torch
        from torch import nn

        params = job.params or {}
        epochs = _get_int(params, "epochs", 10)
        batch = _get_int(params, "batch_size", 64)
        lr = _get_float(params, "lr", 1e-3)
        in_dim = _get_int(params, "in_dim", 16)
        seed = _get_int(params, "seed", 1337)
        device = "cuda" if torch.cuda.is_available() else "cpu"
        torch.manual_seed(seed)

        class TinyMLP(nn.Module):
            def __init__(self, d: int) -> None:
                super().__init__()
                self.net = nn.Sequential(
                    nn.Linear(d, 32), nn.ReLU(),
                    nn.Linear(32, 16), nn.ReLU(),
                    nn.Linear(16, 1)
                )

            def forward(self, x):
                return self.net(x)

        model = TinyMLP(in_dim).to(device)
        opt = torch.optim.AdamW(model.parameters(), lr=lr)
        loss_fn = nn.BCEWithLogitsLoss()

        def make_batch(n: int) -> Tuple["torch.Tensor", "torch.Tensor"]:
            x = torch.randn(n, in_dim, device=device)
            # Rule-based label: sum(x) + noise > 0 -> 1 else 0
            y = (x.sum(dim=1) + 0.1 * torch.randn(n, device=device) > 0).float()
            return x, y

        start_epoch = 0
        if job.checkpoint:
            try:
                # Lightweight state restore (only epoch)
                start_epoch = int(job.checkpoint.get("epoch", 0))
            except Exception:
                start_epoch = 0

        last_loss = float("inf")
        for epoch in range(start_epoch, epochs):
            model.train()
            x, y = make_batch(batch)
            opt.zero_grad(set_to_none=True)
            logits = model(x).squeeze(1)
            loss = loss_fn(logits, y)
            loss.backward()
            opt.step()
            last_loss = float(loss.detach().cpu().item())
            log.info("train_epoch",
                     extra={"extra": {**log_ctx, "epoch": epoch + 1, "bce_loss": round(last_loss, 6)}})

        # Return a small checkpoint (epoch only) to keep it storage-friendly
        return TrainResult(
            status="ok",
            epochs=epochs,
            metrics={"bce_loss": last_loss},
            checkpoint={"epoch": epochs},
        )
    except Exception as e:
        log.warning("torch_trainer_unavailable_or_failed",
                    extra={"extra": {**log_ctx, "reason": str(e)}})
        return TrainResult(status="failed", epochs=0, metrics={"error": str(e)}, checkpoint=None)


# ---------------------------
# Worker
# ---------------------------

@dataclasses.dataclass
class WorkerSettings:
    jobs_root: Path
    log_dir: Path
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    concurrency: int = 1
    poll_interval: float = 1.0
    max_running: int = 1000
    stale_reclaim_seconds: float = 900.0  # 15 min
    log_level: str = "INFO"


class TrainingWorker:
    def __init__(self, cfg: WorkerSettings) -> None:
        self.cfg = cfg
        self.queue = FileQueue(cfg.jobs_root)
        self._stop = asyncio.Event()
        self._http_thread = HttpServerThread(cfg.http_host, cfg.http_port)
        self._tasks: list[asyncio.Task] = []
        self._pidfile = cfg.log_dir / "training_worker.pid"

    def start_http(self) -> None:
        self._http_thread.start()

    async def start(self) -> None:
        self._write_pidfile()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self.stop(s)))
        self.start_http()
        workers = max(1, self.cfg.concurrency)
        for i in range(workers):
            self._tasks.append(asyncio.create_task(self._worker_loop(i)))
        log.info("worker_started", extra={"extra": {"concurrency": workers}})

    async def stop(self, sig: Optional[signal.Signals] = None) -> None:
        if sig:
            log.info("worker_stopping", extra={"extra": {"signal": int(sig)}})
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._http_thread.shutdown()
        self._remove_pidfile()
        log.info("worker_stopped")

    async def _worker_loop(self, slot: int) -> None:
        while not self._stop.is_set():
            t0 = time.perf_counter()
            try:
                # Reclaim stale jobs periodically
                if random.random() < 0.05:
                    reclaimed = self.queue.reclaim_stale(self.cfg.stale_reclaim_seconds)
                    if reclaimed:
                        log.warning("reclaimed_jobs", extra={"extra": {"count": reclaimed}})

                claim = self.queue.claim()
                if not claim:
                    await asyncio.sleep(self.cfg.poll_interval)
                    M_LOOP_LAT.set(time.perf_counter() - t0)
                    continue

                _src, running_path = claim
                M_JOBS_TOTAL.inc(1)
                M_RUNNING.set(M_RUNNING.value + 1)
                await self._run_one(slot, running_path)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("worker_loop_error", extra={"extra": {"slot": slot}})
                await asyncio.sleep(min(2.0, self.cfg.poll_interval))
            finally:
                M_LOOP_LAT.set(time.perf_counter() - t0)

    def _persist_running(self, running_path: Path, job: JobConfig) -> None:
        write_json_atomic(running_path, job.to_dict())

    async def _run_one(self, slot: int, running_path: Path) -> None:
        # Read job
        job = JobConfig.from_path(running_path)
        log_ctx = {"job_id": job.id, "slot": slot, "attempt": job.attempt}
        log.info("job_started", extra={"extra": log_ctx})

        tname = job.trainer
        try:
            trainer = _load_trainer(tname)
        except Exception as e:
            log.exception("trainer_load_failed", extra={"extra": {**log_ctx, "trainer": tname}})
            job.attempt += 1
            self._persist_running(running_path, job)
            self._finalize(running_path, success=False, log_ctx=log_ctx, error=str(e))
            return

        # Run trainer in thread to avoid blocking loop if heavy (even for pure Python)
        loop = asyncio.get_running_loop()
        result: TrainResult
        try:
            result = await loop.run_in_executor(
                None, functools.partial(trainer, job, log_ctx)
            )
        except Exception as e:
            result = TrainResult(status="failed", epochs=0, metrics={"error": str(e)}, checkpoint=None)

        # Persist checkpoint
        if result.get("checkpoint") is not None:
            job.checkpoint = result["checkpoint"]

        # Decide success/failure & retries
        ok = str(result.get("status", "failed")).lower() == "ok"
        if ok:
            job.attempt = job.attempt  # unchanged
        else:
            job.attempt += 1

        # Update metrics & logs
        metrics = result.get("metrics", {})
        log.info("job_finished", extra={"extra": {**log_ctx, "status": "ok" if ok else "failed", "metrics": metrics}})

        # Persist updated running file with checkpoint/attempts before moving
        self._persist_running(running_path, job)

        if ok or job.attempt > job.max_retries:
            self._finalize(running_path, success=ok, log_ctx=log_ctx,
                           error=None if ok else f"exceeded_retries({job.max_retries})")
        else:
            # Backoff, then requeue to ready with updated attempt count
            backoff = job.backoff_seconds * (2 ** max(0, job.attempt - 1))
            log.warning("job_retrying",
                        extra={"extra": {**log_ctx, "attempt": job.attempt, "backoff_sec": backoff}})
            await asyncio.sleep(min(backoff, 60.0))
            # Move back to ready by renaming file name to job.id.json
            target = self.queue.ready / f"{job.id}.json"
            write_json_atomic(target, job.to_dict())
            try:
                os.remove(running_path)
            except FileNotFoundError:
                pass
        M_RUNNING.set(max(0.0, M_RUNNING.value - 1))

    def _finalize(self, running_path: Path, success: bool, log_ctx: Dict[str, Any], error: Optional[str]) -> None:
        dst = self.queue.complete(running_path, success=success)
        if success:
            M_JOBS_OK.inc(1)
        else:
            M_JOBS_FAIL.inc(1)
            if error:
                log.error("job_failed", extra={"extra": {**log_ctx, "error": error}})
        log.info("job_archived", extra={"extra": {**log_ctx, "success": success, "dst": str(dst)}})

    def _write_pidfile(self) -> None:
        self.cfg.log_dir.mkdir(parents=True, exist_ok=True)
        with self._pidfile.open("w", encoding="utf-8") as f:
            f.write(str(os.getpid()))

    def _remove_pidfile(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self._pidfile.unlink()


# ---------------------------
# CLI
# ---------------------------

def _parse_args(argv: Optional[Iterable[str]] = None) -> WorkerSettings:
    p = argparse.ArgumentParser(description="NeuroForge Training Worker")
    p.add_argument("--jobs-root", type=Path, required=True,
                   help="Root folder with subdirs: ready/running/done/failed")
    p.add_argument("--log-dir", type=Path, default=Path("./logs"))
    p.add_argument("--http-host", type=str, default="0.0.0.0")
    p.add_argument("--http-port", type=int, default=8080)
    p.add_argument("--concurrency", type=int, default=1)
    p.add_argument("--poll-interval", type=float, default=1.0)
    p.add_argument("--stale-reclaim-seconds", type=float, default=900.0)
    p.add_argument("--log-level", type=str, default="INFO")
    ns = p.parse_args(argv)

    return WorkerSettings(
        jobs_root=ns.jobs_root,
        log_dir=ns.log_dir,
        http_host=ns.http_host,
        http_port=ns.http_port,
        concurrency=max(1, ns.concurrency),
        poll_interval=max(0.05, ns.poll_interval),
        stale_reclaim_seconds=max(60.0, ns.stale_reclaim_seconds),
        log_level=ns.log_level.upper(),
    )


async def _amain(cfg: WorkerSettings) -> None:
    setup_logging(cfg.log_dir, cfg.log_level)
    worker = TrainingWorker(cfg)
    await worker.start()
    try:
        # Run until stop signal
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        await worker.stop()


def main() -> None:
    cfg = _parse_args()
    try:
        asyncio.run(_amain(cfg))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
